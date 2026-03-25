package controller

import (
	"errors"
	"fmt"
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

type codexDeviceApproveRequest struct {
	UserCode string `json:"user_code"`
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
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

func CodexIssuerApproveDeviceCode(c *gin.Context) {
	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		redirectCodexIssuerToWebLogin(c, "/codex/device", "Sign in to approve a device code.")
		return
	}

	userCode := strings.TrimSpace(c.PostForm("user_code"))
	if userCode == "" {
		redirectCodexIssuerToDevicePage(c, "User code is required.")
		return
	}

	approved, err := service.ApproveCodexDeviceCode(userCode, user.Id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if !approved {
		redirectCodexIssuerToDevicePage(c, "Device code not found.")
		return
	}
	redirectCodexIssuerToDevicePage(c, "Approved device code.")
}

func CodexIssuerAuthorizeContext(c *gin.Context) {
	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		common.ApiErrorMsg(c, "未登录")
		return
	}

	common.ApiSuccess(c, gin.H{
		"id":           user.Id,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"email":        user.Email,
	})
}

func CodexIssuerDeviceContext(c *gin.Context) {
	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		common.ApiErrorMsg(c, "未登录")
		return
	}

	common.ApiSuccess(c, gin.H{
		"user":         buildCodexIssuerContextUser(user),
		"device_codes": service.ListCodexDeviceCodes(),
	})
}

func CodexIssuerApproveDeviceCodeAPI(c *gin.Context) {
	user, ok := getCodexIssuerCurrentUser(c)
	if !ok {
		common.ApiErrorMsg(c, "未登录")
		return
	}

	var req codexDeviceApproveRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorMsg(c, "invalid json body")
		return
	}

	userCode := strings.TrimSpace(req.UserCode)
	if userCode == "" {
		common.ApiErrorMsg(c, "User code is required.")
		return
	}

	approved, err := service.ApproveCodexDeviceCode(userCode, user.Id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if !approved {
		common.ApiErrorMsg(c, "Device code not found.")
		return
	}

	common.ApiSuccess(c, gin.H{
		"message":      "Approved device code.",
		"device_codes": service.ListCodexDeviceCodes(),
	})
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

func redirectCodexIssuerToDevicePage(c *gin.Context, message string) {
	target := "/codex/device"
	if trimmed := strings.TrimSpace(message); trimmed != "" {
		target += "?message=" + url.QueryEscape(trimmed)
	}
	c.Redirect(http.StatusFound, target)
}

func buildCodexIssuerContextUser(user *model.User) gin.H {
	return gin.H{
		"id":           user.Id,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"email":        user.Email,
	}
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
