package controller

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type codexDeviceTokenRequest struct {
	DeviceAuthID string `json:"device_auth_id"`
	UserCode     string `json:"user_code"`
}

type codexIssuerTokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token"`
	SubjectToken string `json:"subject_token"`
}

func CodexIssuerAuthorize(c *gin.Context) {
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is required"})
		return
	}

	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		redirectCodexIssuerToWebLogin(c, c.Request.URL.RequestURI(), "")
		return
	}

	renderCodexIssuerAuthorizePage(c, user, "")
}

func CodexIssuerAuthorizeDecision(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid form body"})
		return
	}

	redirectURI := strings.TrimSpace(c.PostForm("redirect_uri"))
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is required"})
		return
	}

	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		redirectCodexIssuerToWebLogin(c, buildCodexIssuerAuthorizeContinueTo(c), "")
		return
	}

	action := strings.TrimSpace(c.PostForm("action"))
	switch action {
	case "approve":
		redirectTarget, err := createCodexIssuerAuthorizeRedirectTarget(c, user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect_uri"})
			return
		}
		c.Redirect(http.StatusFound, redirectTarget)
	case "cancel":
		redirectTarget, err := addAuthorizeErrorParams(redirectURI, "access_denied", c.PostForm("state"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect_uri"})
			return
		}
		c.Redirect(http.StatusFound, redirectTarget)
	default:
		renderCodexIssuerAuthorizePage(c, user, "Please choose Confirm or Cancel.")
	}
}

func createCodexIssuerAuthorizeRedirectTarget(c *gin.Context, user *model.User) (string, error) {
	redirectURI := firstNonEmpty(c.PostForm("redirect_uri"), c.Query("redirect_uri"))
	codeChallenge := firstNonEmpty(c.PostForm("code_challenge"), c.Query("code_challenge"))
	clientID := firstNonEmpty(c.PostForm("client_id"), c.Query("client_id"))
	state := firstNonEmpty(c.PostForm("state"), c.Query("state"))

	code, err := service.CreateCodexBrowserAuthorizationCode(
		user.Id,
		codeChallenge,
		redirectURI,
		clientID,
	)
	if err != nil {
		return "", err
	}

	redirectTarget, err := addAuthorizeParams(redirectURI, code, state)
	if err != nil {
		return "", err
	}
	return redirectTarget, nil
}

func CodexIssuerBrowserLogin(c *gin.Context) {
	continueTo := normalizeCodexIssuerContinueTo(c.PostForm("continue_to"), "/oauth/authorize")
	if !common.PasswordLoginEnabled {
		redirectCodexIssuerToWebLogin(c, continueTo, "Password login is disabled.")
		return
	}

	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	if username == "" || password == "" {
		redirectCodexIssuerToWebLogin(c, continueTo, "Username and password are required.")
		return
	}

	user := model.User{
		Username: username,
		Password: password,
	}
	if err := user.ValidateAndFill(); err != nil {
		redirectCodexIssuerToWebLogin(c, continueTo, "Invalid username or password.")
		return
	}
	if model.IsTwoFAEnabled(user.Id) {
		redirectCodexIssuerToWebLogin(c, continueTo, "This account has 2FA enabled. Sign in on the dashboard first, then retry.")
		return
	}
	if err := setCodexIssuerBrowserSession(c, &user); err != nil {
		common.ApiError(c, err)
		return
	}
	c.Redirect(http.StatusFound, continueTo)
}

func CodexIssuerToken(c *gin.Context) {
	req, ok := parseCodexIssuerTokenRequest(c)
	if !ok {
		return
	}

	grantType := strings.TrimSpace(req.GrantType)
	switch grantType {
	case "authorization_code":
		tokens, err := service.ExchangeCodexIssuedAuthorizationCode(
			req.Code,
			req.CodeVerifier,
			req.ClientID,
			req.RedirectURI,
		)
		if err != nil {
			writeCodexIssuerTokenError(c, err)
			return
		}
		writeCodexIssuerTokens(c, tokens)
	case "refresh_token":
		tokens, err := service.RefreshCodexIssuedTokens(req.RefreshToken)
		if err != nil {
			writeCodexIssuerTokenError(c, err)
			return
		}
		writeCodexIssuerTokens(c, tokens)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		res, err := service.ExchangeCodexIssuedSubjectToken(req.SubjectToken)
		if err != nil {
			writeCodexIssuerTokenError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token":      res.AccessToken,
			"token_type":        res.TokenType,
			"expires_in":        res.ExpiresIn,
			"issued_token_type": res.IssuedTokenType,
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported grant_type: %s", grantType)})
	}
}

func parseCodexIssuerTokenRequest(c *gin.Context) (*codexIssuerTokenRequest, bool) {
	contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
	req := &codexIssuerTokenRequest{}

	switch {
	case strings.Contains(contentType, "application/json"):
		if err := common.DecodeJson(c.Request.Body, req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
			return nil, false
		}
		return req, true
	case contentType == "", strings.Contains(contentType, "application/x-www-form-urlencoded"), strings.Contains(contentType, "multipart/form-data"):
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid form body"})
			return nil, false
		}
		req.GrantType = c.PostForm("grant_type")
		req.Code = c.PostForm("code")
		req.CodeVerifier = c.PostForm("code_verifier")
		req.ClientID = c.PostForm("client_id")
		req.RedirectURI = c.PostForm("redirect_uri")
		req.RefreshToken = c.PostForm("refresh_token")
		req.SubjectToken = c.PostForm("subject_token")
		return req, true
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected application/x-www-form-urlencoded or application/json"})
		return nil, false
	}
}

func CodexIssuerCreateDeviceCode(c *gin.Context) {
	record, err := service.CreateCodexDeviceAuthorization()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"device_auth_id": record.DeviceAuthID,
		"user_code":      record.UserCode,
		"interval":       record.Interval,
	})
}

func CodexIssuerPollDeviceCode(c *gin.Context) {
	var req codexDeviceTokenRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json body"})
		return
	}

	result, err := service.PollCodexDeviceAuthorization(req.DeviceAuthID, req.UserCode)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrCodexDeviceCodePending):
			c.JSON(http.StatusNotFound, gin.H{"status": "pending"})
		case errors.Is(err, service.ErrCodexDeviceCodeNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown device code"})
		default:
			common.ApiError(c, err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authorization_code": result.AuthorizationCode,
		"code_challenge":     result.CodeChallenge,
		"code_verifier":      result.CodeVerifier,
	})
}

func CodexIssuerDevicePage(c *gin.Context) {
	if _, ok := getCodexIssuerCurrentUser(c); !ok {
		redirectCodexIssuerToWebLogin(c, "/codex/device", "Sign in to approve a device code.")
		return
	}
	renderCodexIssuerDevicePage(c, "")
}

func CodexIssuerApproveDeviceCode(c *gin.Context) {
	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		redirectCodexIssuerToWebLogin(c, "/codex/device", "Sign in to approve a device code.")
		return
	}

	userCode := strings.TrimSpace(c.PostForm("user_code"))
	if userCode == "" {
		renderCodexIssuerDevicePage(c, "User code is required.")
		return
	}

	approved, err := service.ApproveCodexDeviceCode(userCode, user.Id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if !approved {
		renderCodexIssuerDevicePage(c, "Device code not found.")
		return
	}
	renderCodexIssuerDevicePage(c, "Approved device code.")
}

func getCodexIssuerCurrentUser(c *gin.Context) (*model.User, bool) {
	session := sessions.Default(c)
	rawID := session.Get("id")
	if rawID == nil {
		return nil, false
	}
	userID := toInt(rawID)
	if userID <= 0 {
		clearCodexIssuerBrowserSession(c)
		return nil, false
	}
	user, err := model.GetUserById(userID, true)
	if err != nil || user.Status != common.UserStatusEnabled {
		clearCodexIssuerBrowserSession(c)
		return nil, false
	}
	return user, true
}

func setCodexIssuerBrowserSession(c *gin.Context, user *model.User) error {
	session := sessions.Default(c)
	session.Set("id", user.Id)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("status", user.Status)
	session.Set("group", user.Group)
	return session.Save()
}

func clearCodexIssuerBrowserSession(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()
}

func writeCodexIssuerTokens(c *gin.Context, tokens *service.CodexIssuedTokens) {
	c.JSON(http.StatusOK, gin.H{
		"id_token":      tokens.IDToken,
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_in":    tokens.ExpiresIn,
		"scope":         tokens.Scope,
		"token_type":    tokens.TokenType,
	})
}

func writeCodexIssuerTokenError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrCodexRefreshTokenInvalid), errors.Is(err, service.ErrCodexRefreshTokenExpired):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": gin.H{
				"code":    "refresh_token_invalidated",
				"message": "refresh token is not recognized by the server",
			},
		})
	case errors.Is(err, service.ErrCodexAuthorizationCodeInvalid),
		errors.Is(err, service.ErrCodexAuthorizationCodeExpired),
		errors.Is(err, service.ErrCodexAuthorizationCodeUsed),
		errors.Is(err, service.ErrCodexPKCEMismatch),
		errors.Is(err, service.ErrCodexRedirectURIMismatch),
		errors.Is(err, service.ErrCodexClientIDMismatch):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		common.ApiError(c, err)
	}
}

func redirectCodexIssuerToWebLogin(c *gin.Context, continueTo string, message string) {
	query := url.Values{}
	query.Set("continue_to", normalizeCodexIssuerContinueTo(continueTo, "/oauth/authorize"))
	if trimmed := strings.TrimSpace(message); trimmed != "" {
		query.Set("auth_message", trimmed)
	}

	target := "/login"
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	c.Redirect(http.StatusFound, target)
}

func renderCodexIssuerLoginPage(c *gin.Context, continueTo string, message string) {
	escapedContinueTo := template.HTMLEscapeString(normalizeCodexIssuerContinueTo(continueTo, "/oauth/authorize"))
	escapedMessage := template.HTMLEscapeString(strings.TrimSpace(message))
	messageHTML := ""
	if escapedMessage != "" {
		messageHTML = `<p class="flash">` + escapedMessage + `</p>`
	}
	body := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Codex Sign In</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7fb; color: #111827; margin: 0; }
    .shell { width: min(28rem, calc(100vw - 2rem)); margin: 4rem auto; background: #fff; border: 1px solid #dbe1ea; border-radius: 18px; padding: 1.5rem; box-shadow: 0 18px 48px rgba(17, 24, 39, 0.08); }
    h1 { margin: 0 0 0.75rem; font-size: 1.45rem; }
    p { color: #4b5563; line-height: 1.5; }
    .flash { background: #fff3cd; color: #7c5a00; border: 1px solid #f1d37a; border-radius: 12px; padding: 0.75rem 0.9rem; }
    form { display: grid; gap: 0.9rem; margin-top: 1rem; }
    label { display: grid; gap: 0.35rem; font-weight: 600; }
    input { padding: 0.8rem 0.9rem; border: 1px solid #cbd5e1; border-radius: 12px; font: inherit; }
    button { border: 0; border-radius: 12px; padding: 0.85rem 1rem; background: #111827; color: #fff; font: inherit; cursor: pointer; }
  </style>
</head>
<body>
  <div class="shell">
    <h1>Sign in to ` + template.HTMLEscapeString(common.SystemName) + `</h1>
    <p>This browser session will be used to complete the Codex authorization flow.</p>
    ` + messageHTML + `
    <form method="post" action="/oauth/login">
      <input type="hidden" name="continue_to" value="` + escapedContinueTo + `" />
      <label>
        Username
        <input name="username" autocomplete="username" />
      </label>
      <label>
        Password
        <input name="password" type="password" autocomplete="current-password" />
      </label>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
}

func renderCodexIssuerAuthorizePage(c *gin.Context, user *model.User, message string) {
	email := strings.TrimSpace(user.Email)
	if email == "" {
		email = "-"
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = "-"
	}
	scopeItems := strings.Fields(strings.TrimSpace(firstNonEmpty(c.Query("scope"), c.PostForm("scope"))))
	if len(scopeItems) == 0 {
		scopeItems = []string{"openid", "profile", "email"}
	}

	scopeRows := make([]string, 0, len(scopeItems))
	for _, scope := range scopeItems {
		scopeRows = append(scopeRows, "<li><code>"+template.HTMLEscapeString(scope)+"</code></li>")
	}

	messageHTML := ""
	if trimmed := template.HTMLEscapeString(strings.TrimSpace(message)); trimmed != "" {
		messageHTML = `<p class="flash">` + trimmed + `</p>`
	}

	body := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize Codex</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7fb; color: #111827; margin: 0; }
    .shell { width: min(34rem, calc(100vw - 2rem)); margin: 4rem auto; background: #fff; border: 1px solid #dbe1ea; border-radius: 18px; padding: 1.5rem; box-shadow: 0 18px 48px rgba(17, 24, 39, 0.08); }
    h1 { margin: 0 0 0.75rem; font-size: 1.45rem; }
    p { color: #4b5563; line-height: 1.5; }
    .flash { background: #fff3cd; color: #7c5a00; border: 1px solid #f1d37a; border-radius: 12px; padding: 0.75rem 0.9rem; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 14px; padding: 1rem; margin: 1rem 0; }
    .grid { display: grid; grid-template-columns: 8rem 1fr; gap: 0.6rem 1rem; }
    ul { margin: 0.6rem 0 0; padding-left: 1.2rem; }
    code { background: #eef2ff; padding: 0.15rem 0.35rem; border-radius: 6px; }
    .actions { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
    button { border: 0; border-radius: 12px; padding: 0.85rem 1rem; font: inherit; cursor: pointer; }
    .cancel { background: #e5e7eb; color: #111827; }
    .confirm { background: #111827; color: #fff; }
  </style>
</head>
<body>
  <div class="shell">
    <h1>Authorize Codex</h1>
    <p>Review the signed-in account, then confirm or cancel this authorization request.</p>
    ` + messageHTML + `
    <div class="card">
      <div class="grid">
        <div>Username</div><div>` + template.HTMLEscapeString(user.Username) + `</div>
        <div>Display name</div><div>` + template.HTMLEscapeString(displayName) + `</div>
        <div>Email</div><div>` + template.HTMLEscapeString(email) + `</div>
        <div>Client ID</div><div><code>` + template.HTMLEscapeString(firstNonEmpty(c.Query("client_id"), c.PostForm("client_id"))) + `</code></div>
      </div>
      <div style="margin-top: 0.9rem;">
        <div>Requested scopes</div>
        <ul>` + strings.Join(scopeRows, "") + `</ul>
      </div>
    </div>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="redirect_uri" value="` + template.HTMLEscapeString(firstNonEmpty(c.Query("redirect_uri"), c.PostForm("redirect_uri"))) + `" />
      <input type="hidden" name="state" value="` + template.HTMLEscapeString(firstNonEmpty(c.Query("state"), c.PostForm("state"))) + `" />
      <input type="hidden" name="client_id" value="` + template.HTMLEscapeString(firstNonEmpty(c.Query("client_id"), c.PostForm("client_id"))) + `" />
      <input type="hidden" name="scope" value="` + template.HTMLEscapeString(firstNonEmpty(c.Query("scope"), c.PostForm("scope"))) + `" />
      <input type="hidden" name="code_challenge" value="` + template.HTMLEscapeString(firstNonEmpty(c.Query("code_challenge"), c.PostForm("code_challenge"))) + `" />
      <div class="actions">
        <button class="cancel" type="submit" name="action" value="cancel">Cancel</button>
        <button class="confirm" type="submit" name="action" value="approve">Confirm</button>
      </div>
    </form>
  </div>
</body>
</html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
}

func renderCodexIssuerDevicePage(c *gin.Context, message string) {
	rows := make([]string, 0)
	for _, record := range service.ListCodexDeviceCodes() {
		status := "no"
		if record.Approved {
			status = "yes"
		}
		rows = append(rows, "<tr><td><code>"+
			template.HTMLEscapeString(record.UserCode)+
			"</code></td><td>"+status+
			"</td><td>"+strconv.Itoa(record.Polls)+
			"</td></tr>")
	}
	tableRows := strings.Join(rows, "")
	if tableRows == "" {
		tableRows = "<tr><td colspan='3'>No active device codes yet.</td></tr>"
	}
	messageHTML := ""
	if trimmed := template.HTMLEscapeString(strings.TrimSpace(message)); trimmed != "" {
		messageHTML = "<p class='flash'><strong>" + trimmed + "</strong></p>"
	}

	body := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Codex Device Auth</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 48rem; padding: 0 1rem; color: #111827; }
    code { background: #f4f4f5; padding: 0.2rem 0.35rem; border-radius: 6px; }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    td, th { border: 1px solid #d1d5db; padding: 0.65rem; text-align: left; }
    form { display: flex; gap: 0.75rem; margin-top: 1rem; }
    input { flex: 1; padding: 0.75rem 0.85rem; border: 1px solid #cbd5e1; border-radius: 12px; }
    button { padding: 0.75rem 1rem; border: 0; border-radius: 12px; background: #111827; color: #fff; cursor: pointer; }
    .flash { background: #ecfccb; border: 1px solid #bef264; color: #365314; border-radius: 12px; padding: 0.8rem 0.9rem; }
  </style>
</head>
<body>
  <h1>Codex Device Auth</h1>
  <p>Open this page after the CLI prints a user code, then approve it here.</p>
  ` + messageHTML + `
  <form method="post" action="/codex/device">
    <input name="user_code" placeholder="Enter the printed user code" />
    <button type="submit">Approve</button>
  </form>
  <table>
    <thead>
      <tr><th>User code</th><th>Approved</th><th>Polls</th></tr>
    </thead>
    <tbody>` + tableRows + `</tbody>
  </table>
</body>
</html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
}

func normalizeCodexIssuerContinueTo(continueTo string, defaultPath string) string {
	value := strings.TrimSpace(continueTo)
	switch {
	case strings.HasPrefix(value, "/oauth/authorize"):
		return value
	case strings.HasPrefix(value, "/codex/device"):
		return "/codex/device"
	case strings.TrimSpace(defaultPath) != "":
		return defaultPath
	default:
		return "/oauth/authorize"
	}
}

func addAuthorizeParams(redirectURI string, code string, state string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("code", code)
	if strings.TrimSpace(state) != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func addAuthorizeErrorParams(redirectURI string, errorCode string, state string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("error", errorCode)
	if strings.TrimSpace(state) != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func buildCodexIssuerAuthorizeContinueTo(c *gin.Context) string {
	query := url.Values{}
	for _, key := range []string{"response_type", "client_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method", "id_token_add_organizations", "codex_cli_simplified_flow", "state", "originator"} {
		if value := strings.TrimSpace(c.PostForm(key)); value != "" {
			query.Set(key, value)
		}
	}
	if encoded := query.Encode(); encoded != "" {
		return "/oauth/authorize?" + encoded
	}
	return "/oauth/authorize"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func toInt(v any) int {
	switch value := v.(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int(value)
	case uint:
		return int(value)
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return int(value)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(value))
		return parsed
	default:
		return 0
	}
}
