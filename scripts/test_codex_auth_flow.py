#!/usr/bin/env python3
"""Codex auth and quota flow smoke test.

This script exercises the local Codex-compatible auth flow end to end:

1. Browser-style login via /oauth/authorize + /oauth/login.
2. Local callback capture for the authorization code.
3. Token exchange via /oauth/token.
4. Refresh token flow via /oauth/token.
5. API token exchange via OAuth token-exchange.
6. Usage inspection via /api/codex/usage (mock-compatible) or /backend-api/wham/usage.
7. Request tests against /backend-api/codex/responses and /backend-api/codex/responses/compact.

The implementation intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import socketserver
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urljoin
from urllib.parse import urlparse
from urllib.request import HTTPCookieProcessor
from urllib.request import HTTPRedirectHandler
from urllib.request import Request
from urllib.request import build_opener


DEFAULT_SCOPE = (
    "openid profile email offline_access "
    "api.connectors.read api.connectors.invoke"
)
DEFAULT_USAGE_PATHS = ["/api/codex/usage", "/backend-api/wham/usage"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_b64url(data: str) -> bytes:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def pkce_code_verifier() -> str:
    return secrets.token_urlsafe(48)


def pkce_code_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT shape")
    payload = decode_b64url(parts[1])
    return json.loads(payload.decode("utf-8"))


def pick_account_id(access_token: str) -> str:
    payload = decode_jwt_payload(access_token)
    auth_claims = payload.get("https://api.openai.com/auth", {})
    if not isinstance(auth_claims, dict):
        raise ValueError("missing auth claims")
    account_id = str(auth_claims.get("chatgpt_account_id", "")).strip()
    if not account_id:
        raise ValueError("missing chatgpt_account_id in access token")
    return account_id


def infer_user_id_from_account_id(account_id: str) -> int:
    value = str(account_id).strip()
    if value.startswith("new-api-account-"):
        suffix = value.removeprefix("new-api-account-")
        if suffix.isdigit():
            return int(suffix)
    return 0


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def log_step(message: str) -> None:
    print(f"[step] {message}")


def log_info(message: str) -> None:
    print(f"[info] {message}")


def log_warn(message: str) -> None:
    print(f"[warn] {message}")


@dataclass
class CallbackResult:
    full_path: str
    params: dict[str, list[str]]


class CallbackState:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: CallbackResult | None = None


class CallbackHandler(BaseHTTPRequestHandler):
    state: CallbackState

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        CallbackHandler.state.result = CallbackResult(
            full_path=self.path,
            params=parse_qs(parsed.query, keep_blank_values=True),
        )
        CallbackHandler.state.event.set()
        body = (
            "<html><body><h1>Codex callback captured</h1>"
            "<p>You can close this page.</p></body></html>"
        ).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None

    def http_error_302(self, req, fp, code, msg, headers):  # type: ignore[override]
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class HttpClient:
    def __init__(self) -> None:
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))
        self.no_redirect_opener = build_opener(
            HTTPCookieProcessor(self.cookie_jar),
            NoRedirectHandler(),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        form: dict[str, Any] | None = None,
        json_body: Any | None = None,
        follow_redirects: bool = True,
        timeout: float = 20.0,
    ) -> tuple[int, dict[str, str], bytes]:
        request_headers = dict(headers or {})
        data = None
        if form is not None:
            data = urlencode(
                {k: "" if v is None else str(v) for k, v in form.items()}
            ).encode("utf-8")
            request_headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        elif json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        req = Request(url, data=data, headers=request_headers, method=method.upper())
        opener = self.opener if follow_redirects else self.no_redirect_opener
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read()
                return resp.getcode(), dict(resp.headers.items()), body
        except HTTPError as exc:
            body = exc.read()
            return exc.code, dict(exc.headers.items()), body

    def get_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        form: dict[str, Any] | None = None,
        json_body: Any | None = None,
        follow_redirects: bool = True,
        timeout: float = 20.0,
    ) -> tuple[int, dict[str, str], Any]:
        status, resp_headers, body = self.request(
            method,
            url,
            headers=headers,
            form=form,
            json_body=json_body,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )
        text = body.decode("utf-8", errors="replace")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
        return status, resp_headers, payload


def start_callback_server(host: str, port: int) -> tuple[ThreadedHTTPServer, CallbackState]:
    state = CallbackState()
    CallbackHandler.state = state
    server = ThreadedHTTPServer((host, port), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


def first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key) or []
    return values[0] if values else ""


def print_usage_summary(label: str, payload: Any) -> None:
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if not isinstance(data, dict):
        log_info(f"{label}: {data}")
        return

    rate_limit = data.get("rate_limit") if isinstance(data.get("rate_limit"), dict) else {}
    primary = rate_limit.get("primary_window") if isinstance(rate_limit.get("primary_window"), dict) else None
    secondary = rate_limit.get("secondary_window") if isinstance(rate_limit.get("secondary_window"), dict) else None

    parts = [
        f"plan={data.get('plan_type', '-')}",
        f"allowed={rate_limit.get('allowed', '-')}",
        f"limit_reached={rate_limit.get('limit_reached', '-')}",
    ]

    if primary:
        parts.append(
            "primary="
            f"{primary.get('used_percent', '-')}"
            f"%/{primary.get('limit_window_seconds', '-')}s"
        )
    if secondary:
        parts.append(
            "secondary="
            f"{secondary.get('used_percent', '-')}"
            f"%/{secondary.get('limit_window_seconds', '-')}s"
        )
    log_info(f"{label}: " + ", ".join(parts))


def fetch_subscription_self(
    client: HttpClient,
    base_url: str,
    *,
    system_access_token: str,
    user_id: int,
) -> Any:
    headers = {"Accept": "application/json"}
    token = system_access_token.strip()
    if token:
        headers["Authorization"] = token
    if user_id > 0:
        headers["New-Api-User"] = str(user_id)
    status, _, payload = client.get_json(
        "GET",
        urljoin(base_url, "/api/subscription/self"),
        headers=headers,
    )
    ensure_ok(status, payload, "fetch /api/subscription/self")
    return payload


def extract_active_subscriptions(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data", {})
    if not isinstance(data, dict):
        return []
    subscriptions = data.get("subscriptions", [])
    if not isinstance(subscriptions, list):
        return []
    result: list[dict[str, Any]] = []
    for item in subscriptions:
        if not isinstance(item, dict):
            continue
        sub = item.get("subscription", {})
        if isinstance(sub, dict):
            result.append(sub)
    return result


def print_subscription_summary(payload: Any) -> None:
    active = extract_active_subscriptions(payload)
    if not active:
        log_warn("当前登录用户没有有效订阅")
        return
    for sub in active:
        log_info(
            "active subscription: "
            f"id={sub.get('id', '-')}, "
            f"plan_id={sub.get('plan_id', '-')}, "
            f"status={sub.get('status', '-')}, "
            f"used={sub.get('amount_used', '-')}, "
            f"total={sub.get('amount_total', '-')}, "
            f"next_reset={sub.get('next_reset_time', '-')}, "
            f"end_time={sub.get('end_time', '-')}"
        )


def ensure_ok(status: int, payload: Any, action: str) -> None:
    if 200 <= status < 300:
        return
    raise RuntimeError(f"{action} failed: status={status}, payload={payload}")


def fetch_usage(
    client: HttpClient,
    base_url: str,
    access_token: str,
    account_id: str,
    usage_paths: list[str],
) -> tuple[str, Any]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "Accept": "application/json",
        "originator": "agent_hub",
    }
    last_status = 0
    last_payload: Any = None
    for path in usage_paths:
        url = urljoin(base_url, path)
        status, _, payload = client.get_json("GET", url, headers=headers)
        if status == HTTPStatus.NOT_FOUND:
            last_status = status
            last_payload = payload
            continue
        ensure_ok(status, payload, f"fetch usage {path}")
        return path, payload
    raise RuntimeError(
        f"usage endpoint not available, last_status={last_status}, payload={last_payload}"
    )


def fetch_models(
    client: HttpClient,
    base_url: str,
    api_token: str,
    account_id: str,
) -> list[str]:
    headers = {
        "Authorization": f"Bearer {api_token}",
        "chatgpt-account-id": account_id,
        "Accept": "application/json",
        "originator": "agent_hub",
    }
    status, _, payload = client.get_json(
        "GET",
        urljoin(base_url, "/backend-api/codex/models?client_version=0.0.0"),
        headers=headers,
    )
    ensure_ok(status, payload, "fetch models")
    models = payload.get("models", []) if isinstance(payload, dict) else []
    result: list[str] = []
    for item in models:
        if isinstance(item, dict):
            slug = str(item.get("slug", "")).strip()
            if slug:
                result.append(slug)
    if not result:
        raise RuntimeError(f"no models returned: {payload}")
    return result


def call_responses_endpoint(
    client: HttpClient,
    base_url: str,
    api_token: str,
    account_id: str,
    path: str,
    model: str,
    prompt: str,
    extra_body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    headers = {
        "Authorization": f"Bearer {api_token}",
        "chatgpt-account-id": account_id,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "OpenAI-Beta": "responses=experimental",
        "originator": "agent_hub",
    }
    body: dict[str, Any] = {
        "model": model,
        "instructions": "",
        "input": prompt,
        "stream": False,
    }
    if extra_body:
        body.update(extra_body)
    status, _, payload = client.get_json(
        "POST",
        urljoin(base_url, path),
        headers=headers,
        json_body=body,
    )
    return status, payload


def extract_limit_reached(payload: Any) -> bool:
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        return False
    rate_limit = data.get("rate_limit", {})
    if not isinstance(rate_limit, dict):
        return False
    return bool(rate_limit.get("limit_reached"))


def extract_allowed(payload: Any) -> bool:
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        return False
    rate_limit = data.get("rate_limit", {})
    if not isinstance(rate_limit, dict):
        return False
    return bool(rate_limit.get("allowed"))


def run_browser_login_flow(
    client: HttpClient,
    base_url: str,
    username: str,
    password: str,
    callback_url: str,
    client_id: str,
    scope: str,
    originator: str,
) -> tuple[str, str]:
    verifier = pkce_code_verifier()
    challenge = pkce_code_challenge(verifier)
    state = "st_" + secrets.token_urlsafe(24)

    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "state": state,
        "originator": originator,
    }
    authorize_path = "/oauth/authorize?" + urlencode(query)
    authorize_url = urljoin(base_url, authorize_path)

    log_step("open authorize page")
    status, _, payload = client.get_json("GET", authorize_url)
    if status not in (HTTPStatus.OK, HTTPStatus.FOUND):
        raise RuntimeError(f"open authorize page failed: status={status}, payload={payload}")

    log_step("submit browser login form")
    status, _, payload = client.get_json(
        "POST",
        urljoin(base_url, "/oauth/login"),
        form={
            "username": username,
            "password": password,
            "continue_to": authorize_path,
        },
    )
    if status not in (HTTPStatus.OK, HTTPStatus.FOUND):
        raise RuntimeError(f"browser login failed: status={status}, payload={payload}")

    log_step("submit authorize confirm form")
    status, headers, payload = client.get_json(
        "POST",
        urljoin(base_url, "/oauth/authorize"),
        form={
            "action": "approve",
            "redirect_uri": callback_url,
            "state": state,
            "client_id": client_id,
            "scope": scope,
            "code_challenge": challenge,
        },
        follow_redirects=False,
    )
    if status != HTTPStatus.FOUND:
        raise RuntimeError(f"authorize confirm failed: status={status}, payload={payload}")
    location = headers.get("Location", "").strip()
    if not location:
        raise RuntimeError("authorize confirm did not return redirect location")
    return verifier, location


def redeem_authorization_code(
    client: HttpClient,
    base_url: str,
    code: str,
    verifier: str,
    client_id: str,
    redirect_uri: str,
) -> Any:
    log_step("exchange authorization code")
    status, _, payload = client.get_json(
        "POST",
        urljoin(base_url, "/oauth/token"),
        form={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        },
    )
    ensure_ok(status, payload, "authorization_code exchange")
    return payload


def refresh_tokens(client: HttpClient, base_url: str, refresh_token: str) -> Any:
    log_step("refresh OAuth tokens")
    status, _, payload = client.get_json(
        "POST",
        urljoin(base_url, "/oauth/token"),
        form={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    ensure_ok(status, payload, "refresh_token exchange")
    return payload


def exchange_api_token(client: HttpClient, base_url: str, subject_token: str) -> Any:
    log_step("exchange ChatGPT token to backend API token")
    status, _, payload = client.get_json(
        "POST",
        urljoin(base_url, "/oauth/token"),
        form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
        },
    )
    ensure_ok(status, payload, "token exchange")
    return payload


def wait_for_callback(state: CallbackState, timeout: float) -> CallbackResult:
    if not state.event.wait(timeout):
        raise TimeoutError(f"callback not received within {timeout:.1f}s")
    if state.result is None:
        raise RuntimeError("callback event set without result")
    return state.result


def maybe_hit_callback(location: str) -> None:
    # The callback server only needs the redirect to happen once. Using the browser
    # redirect here keeps the flow close to the real Codex callback behavior.
    client = HttpClient()
    status, _, payload = client.get_json("GET", location)
    if status >= 400:
        raise RuntimeError(f"callback GET failed: status={status}, payload={payload}")


def summarize_response_payload(payload: Any) -> str:
    if isinstance(payload, dict):
        if "output_text" in payload:
            return str(payload.get("output_text", "")).strip()
        if "status" in payload or "id" in payload:
            return compact_json(
                {k: payload.get(k) for k in ("id", "status", "output_text") if k in payload}
            )
        return compact_json(payload)[:240]
    return str(payload)[:240]


def extract_error_code(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("code", "")).strip()
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Test local Codex auth + quota flow.")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000", help="new-api base URL")
    parser.add_argument("--username", required=True, help="Browser login username")
    parser.add_argument("--password", required=True, help="Browser login password")
    parser.add_argument(
        "--client-id",
        default="app_EMoamEEZ73f0CkXaXp7hrann",
        help="OAuth client_id used by Codex CLI",
    )
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help="OAuth scope")
    parser.add_argument("--originator", default="agent_hub", help="originator query/header")
    parser.add_argument("--callback-host", default="127.0.0.1", help="Local callback host")
    parser.add_argument("--callback-port", type=int, default=1455, help="Local callback port")
    parser.add_argument("--callback-timeout", type=float, default=10.0, help="Callback wait timeout seconds")
    parser.add_argument("--model", default="", help="Model slug, defaults to first returned model")
    parser.add_argument("--prompt", default="Reply with exactly OK.", help="Prompt sent to responses endpoints")
    parser.add_argument("--responses", type=int, default=1, help="How many /backend-api/codex/responses calls to make")
    parser.add_argument(
        "--compact-responses",
        type=int,
        default=1,
        help="How many /backend-api/codex/responses/compact calls to make",
    )
    parser.add_argument(
        "--until-limit",
        action="store_true",
        help="Keep calling endpoints until usage reports limit_reached or counts are exhausted",
    )
    parser.add_argument(
        "--ignore-initial-limit",
        action="store_true",
        help="Continue requests even if the initial usage already reports limit reached",
    )
    parser.add_argument(
        "--system-access-token",
        default="",
        help="new-api system access token used for /api/subscription/self",
    )
    parser.add_argument(
        "--new-api-user-id",
        type=int,
        default=0,
        help="new-api user id used for /api/subscription/self; defaults to infer from account_id",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/") + "/"
    callback_url = f"http://{args.callback_host}:{args.callback_port}/auth/callback"

    server, callback_state = start_callback_server(args.callback_host, args.callback_port)
    client = HttpClient()

    try:
        verifier, redirect_location = run_browser_login_flow(
            client,
            base_url,
            args.username,
            args.password,
            callback_url,
            args.client_id,
            args.scope,
            args.originator,
        )

        log_step("follow authorize redirect into local callback")
        maybe_hit_callback(redirect_location)
        callback = wait_for_callback(callback_state, args.callback_timeout)
        code = first_value(callback.params, "code")
        state = first_value(callback.params, "state")
        if not code:
            raise RuntimeError(f"callback missing code: {callback.full_path}")
        log_info(f"callback received code, state={state or '-'}")

        token_payload = redeem_authorization_code(
            client,
            base_url,
            code,
            verifier,
            args.client_id,
            callback_url,
        )
        refresh_payload = refresh_tokens(
            client,
            base_url,
            str(token_payload.get("refresh_token", "")),
        )
        refreshed_access_token = str(refresh_payload.get("access_token", "")).strip()
        if not refreshed_access_token:
            raise RuntimeError(f"refresh response missing access_token: {refresh_payload}")

        api_token_payload = exchange_api_token(client, base_url, refreshed_access_token)
        api_token = str(api_token_payload.get("access_token", "")).strip()
        if not api_token:
            raise RuntimeError(f"token exchange missing access_token: {api_token_payload}")

        account_id = pick_account_id(refreshed_access_token)
        new_api_user_id = args.new_api_user_id or infer_user_id_from_account_id(account_id)
        log_info(f"account_id={account_id}")
        if new_api_user_id > 0:
            log_info(f"new_api_user_id={new_api_user_id}")

        usage_path, usage_payload = fetch_usage(
            client,
            base_url,
            api_token,
            account_id,
            DEFAULT_USAGE_PATHS,
        )
        log_info(f"usage endpoint={usage_path}")
        print_usage_summary("initial usage", usage_payload)
        if not args.ignore_initial_limit and (
            extract_limit_reached(usage_payload) or not extract_allowed(usage_payload)
        ):
            log_warn("初始 usage 已显示当前账户不可用，先检查订阅状态")
            try:
                subscription_payload = fetch_subscription_self(
                    client,
                    base_url,
                    system_access_token=args.system_access_token,
                    user_id=new_api_user_id,
                )
                print_subscription_summary(subscription_payload)
            except Exception as exc:  # noqa: BLE001
                log_warn(f"读取 /api/subscription/self 失败: {exc}")
            log_warn(
                "中止后续 responses 测试。通常原因是：没有有效订阅，套餐额度已耗尽，或当前滑动窗口已经触顶。"
            )
            return 2

        model = args.model
        if not model:
            models = fetch_models(client, base_url, api_token, account_id)
            model = models[0]
        log_info(f"model={model}")

        endpoint_plan = [
            ("/backend-api/codex/responses", args.responses, None),
            (
                "/backend-api/codex/responses/compact",
                args.compact_responses,
                {"reasoning": {"effort": "low"}},
            ),
        ]

        for path, max_calls, extra_body in endpoint_plan:
            for index in range(max_calls):
                status, payload = call_responses_endpoint(
                    client,
                    base_url,
                    api_token,
                    account_id,
                    path,
                    model,
                    args.prompt,
                    extra_body=extra_body,
                )
                log_info(
                    f"{path} #{index + 1}: status={status}, summary={summarize_response_payload(payload)}"
                )
                if extract_error_code(payload) == "model_price_error":
                    log_warn(
                        "当前模型未配置倍率/价格。请先在后台配置该模型价格，或用 --model 指定一个已配置价格的模型。"
                    )
                    return 3
                usage_path, usage_payload = fetch_usage(
                    client,
                    base_url,
                    api_token,
                    account_id,
                    DEFAULT_USAGE_PATHS,
                )
                print_usage_summary(f"usage after {path} #{index + 1}", usage_payload)
                if args.until_limit and extract_limit_reached(usage_payload):
                    log_warn(f"limit reached after {path} #{index + 1}")
                    break
            if args.until_limit and extract_limit_reached(usage_payload):
                break

        log_step("done")
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
