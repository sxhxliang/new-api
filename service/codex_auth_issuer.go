package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const (
	codexIssuerAuthCodeTTL      = 5 * time.Minute
	codexIssuerDeviceCodeTTL    = 15 * time.Minute
	codexIssuerAccessTokenTTL   = time.Hour
	codexIssuerRefreshTokenTTL  = 30 * 24 * time.Hour
	codexIssuerDeviceCodePollIn = 5
	codexIssuerScope            = "openid profile email offline_access"
	codexIssuerPlanType         = "plus"
)

var (
	ErrCodexAuthorizationCodeInvalid = errors.New("codex issuer: authorization code invalid")
	ErrCodexAuthorizationCodeExpired = errors.New("codex issuer: authorization code expired")
	ErrCodexAuthorizationCodeUsed    = errors.New("codex issuer: authorization code already used")
	ErrCodexPKCEMismatch             = errors.New("codex issuer: pkce verification failed")
	ErrCodexRedirectURIMismatch      = errors.New("codex issuer: redirect uri mismatch")
	ErrCodexClientIDMismatch         = errors.New("codex issuer: client id mismatch")
	ErrCodexRefreshTokenInvalid      = errors.New("codex issuer: refresh token invalid")
	ErrCodexRefreshTokenExpired      = errors.New("codex issuer: refresh token expired")
	ErrCodexDeviceCodeNotFound       = errors.New("codex issuer: device code not found")
	ErrCodexDeviceCodePending        = errors.New("codex issuer: device code pending")
)

type CodexIssuedTokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
	TokenType    string
}

type CodexTokenExchangeResult struct {
	AccessToken     string
	TokenType       string
	ExpiresIn       int
	IssuedTokenType string
}

type CodexAPITokenClaims struct {
	UserID    int
	AccountID string
	ExpiresAt int64
}

type CodexDeviceAuthorization struct {
	DeviceAuthID string
	UserCode     string
	Interval     string
}

type CodexDeviceAuthorizationExchange struct {
	AuthorizationCode string
	CodeChallenge     string
	CodeVerifier      string
}

type CodexDeviceCodeView struct {
	DeviceAuthID string    `json:"device_auth_id"`
	UserCode     string    `json:"user_code"`
	Approved     bool      `json:"approved"`
	Polls        int       `json:"polls"`
	CreatedAt    time.Time `json:"created_at"`
}

type codexAuthCodeRecord struct {
	Code          string
	UserID        int
	CodeChallenge string
	RedirectURI   string
	ClientID      string
	CreatedAt     time.Time
	UsedAt        *time.Time
}

type codexDeviceCodeRecord struct {
	DeviceAuthID      string
	UserCode          string
	AuthorizationCode string
	CodeChallenge     string
	CodeVerifier      string
	Approved          bool
	UserID            int
	Polls             int
	CreatedAt         time.Time
}

type codexRefreshTokenPayload struct {
	Type      string `json:"typ"`
	UserID    int    `json:"uid"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

type codexAuthIssuerState struct {
	mu          sync.Mutex
	authCodes   map[string]*codexAuthCodeRecord
	deviceCodes map[string]*codexDeviceCodeRecord
}

var defaultCodexAuthIssuer = &codexAuthIssuerState{
	authCodes:   make(map[string]*codexAuthCodeRecord),
	deviceCodes: make(map[string]*codexDeviceCodeRecord),
}

func CreateCodexBrowserAuthorizationCode(userID int, codeChallenge string, redirectURI string, clientID string) (string, error) {
	return defaultCodexAuthIssuer.createBrowserAuthorizationCode(userID, codeChallenge, redirectURI, clientID)
}

func ExchangeCodexIssuedAuthorizationCode(code string, codeVerifier string, clientID string, redirectURI string) (*CodexIssuedTokens, error) {
	return defaultCodexAuthIssuer.exchangeAuthorizationCode(code, codeVerifier, clientID, redirectURI)
}

func RefreshCodexIssuedTokens(refreshToken string) (*CodexIssuedTokens, error) {
	userID, err := parseCodexRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	user, err := model.GetUserById(userID, true)
	if err != nil {
		return nil, ErrCodexRefreshTokenInvalid
	}
	if user.Status != common.UserStatusEnabled {
		return nil, ErrCodexRefreshTokenInvalid
	}
	return buildCodexIssuedTokens(user)
}

func ExchangeCodexIssuedSubjectToken(subjectToken string) (*CodexTokenExchangeResult, error) {
	userID, err := extractCodexUserIDFromAccessToken(subjectToken)
	if err != nil {
		return nil, ErrCodexAuthorizationCodeInvalid
	}
	user, err := model.GetUserById(userID, true)
	if err != nil {
		return nil, ErrCodexAuthorizationCodeInvalid
	}
	if user.Status != common.UserStatusEnabled {
		return nil, ErrCodexAuthorizationCodeInvalid
	}

	accessToken, err := issueCodexAPIToken(user.Id)
	if err != nil {
		return nil, err
	}
	return &CodexTokenExchangeResult{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(codexIssuerAccessTokenTTL.Seconds()),
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}, nil
}

func ValidateCodexIssuedAPIToken(token string) (*CodexAPITokenClaims, error) {
	trimmed := strings.TrimSpace(token)
	if !strings.HasPrefix(trimmed, "atk_") {
		return nil, ErrCodexRefreshTokenInvalid
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "atk_"), ".", 2)
	if len(parts) != 2 {
		return nil, ErrCodexRefreshTokenInvalid
	}
	if !hmac.Equal([]byte(signCodexRefreshToken(parts[0])), []byte(parts[1])) {
		return nil, ErrCodexRefreshTokenInvalid
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrCodexRefreshTokenInvalid
	}
	var payload codexRefreshTokenPayload
	if err = common.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrCodexRefreshTokenInvalid
	}
	if payload.Type != "api_token" || payload.UserID <= 0 {
		return nil, ErrCodexRefreshTokenInvalid
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, ErrCodexRefreshTokenExpired
	}
	return &CodexAPITokenClaims{
		UserID:    payload.UserID,
		AccountID: CodexAccountIDForUserID(payload.UserID),
		ExpiresAt: payload.ExpiresAt,
	}, nil
}

func ValidateCodexBackendToken(token string) (*CodexAPITokenClaims, error) {
	if claims, err := ValidateCodexIssuedAPIToken(token); err == nil {
		return claims, nil
	}

	userID, accountID, expiresAt, err := extractCodexAccessTokenClaims(token)
	if err != nil {
		return nil, ErrCodexRefreshTokenInvalid
	}
	return &CodexAPITokenClaims{
		UserID:    userID,
		AccountID: accountID,
		ExpiresAt: expiresAt,
	}, nil
}

func CodexAccountIDForUserID(userID int) string {
	return fmt.Sprintf("new-api-account-%d", userID)
}

func CreateCodexDeviceAuthorization() (*CodexDeviceAuthorization, error) {
	return defaultCodexAuthIssuer.createDeviceAuthorization()
}

func PollCodexDeviceAuthorization(deviceAuthID string, userCode string) (*CodexDeviceAuthorizationExchange, error) {
	return defaultCodexAuthIssuer.pollDeviceAuthorization(deviceAuthID, userCode)
}

func ApproveCodexDeviceCode(userCode string, userID int) (bool, error) {
	return defaultCodexAuthIssuer.approveDeviceCode(userCode, userID)
}

func ListCodexDeviceCodes() []CodexDeviceCodeView {
	return defaultCodexAuthIssuer.listDeviceCodes()
}

func (s *codexAuthIssuerState) createBrowserAuthorizationCode(userID int, codeChallenge string, redirectURI string, clientID string) (string, error) {
	code, err := randomToken("auth", 24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)
	s.authCodes[code] = &codexAuthCodeRecord{
		Code:          code,
		UserID:        userID,
		CodeChallenge: strings.TrimSpace(codeChallenge),
		RedirectURI:   strings.TrimSpace(redirectURI),
		ClientID:      strings.TrimSpace(clientID),
		CreatedAt:     now,
	}
	return code, nil
}

func (s *codexAuthIssuerState) exchangeAuthorizationCode(code string, codeVerifier string, clientID string, redirectURI string) (*CodexIssuedTokens, error) {
	now := time.Now()
	s.mu.Lock()
	s.cleanupLocked(now)

	record, ok := s.authCodes[strings.TrimSpace(code)]
	if !ok {
		s.mu.Unlock()
		return nil, ErrCodexAuthorizationCodeInvalid
	}
	if now.Sub(record.CreatedAt) > codexIssuerAuthCodeTTL {
		delete(s.authCodes, record.Code)
		s.mu.Unlock()
		return nil, ErrCodexAuthorizationCodeExpired
	}
	if record.UsedAt != nil {
		s.mu.Unlock()
		return nil, ErrCodexAuthorizationCodeUsed
	}
	if record.RedirectURI != "" && strings.TrimSpace(redirectURI) != "" && record.RedirectURI != strings.TrimSpace(redirectURI) {
		s.mu.Unlock()
		return nil, ErrCodexRedirectURIMismatch
	}
	if record.ClientID != "" && strings.TrimSpace(clientID) != "" && record.ClientID != strings.TrimSpace(clientID) {
		s.mu.Unlock()
		return nil, ErrCodexClientIDMismatch
	}
	if !verifyCodeChallenge(record.CodeChallenge, codeVerifier) {
		s.mu.Unlock()
		return nil, ErrCodexPKCEMismatch
	}
	usedAt := now
	record.UsedAt = &usedAt
	userID := record.UserID
	delete(s.authCodes, record.Code)
	s.mu.Unlock()

	user, err := model.GetUserById(userID, true)
	if err != nil {
		return nil, ErrCodexAuthorizationCodeInvalid
	}
	if user.Status != common.UserStatusEnabled {
		return nil, ErrCodexAuthorizationCodeInvalid
	}
	return buildCodexIssuedTokens(user)
}

func (s *codexAuthIssuerState) createDeviceAuthorization() (*CodexDeviceAuthorization, error) {
	deviceAuthID, err := randomToken("device-auth", 20)
	if err != nil {
		return nil, err
	}
	authCode, err := randomToken("device-code", 24)
	if err != nil {
		return nil, err
	}
	verifier, err := common.GenerateRandomCharsKey(48)
	if err != nil {
		return nil, err
	}
	challenge := pkceCodeChallenge(verifier)
	userCode, err := randomUserCode()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)
	s.deviceCodes[deviceAuthID] = &codexDeviceCodeRecord{
		DeviceAuthID:      deviceAuthID,
		UserCode:          userCode,
		AuthorizationCode: authCode,
		CodeChallenge:     challenge,
		CodeVerifier:      verifier,
		CreatedAt:         now,
	}
	return &CodexDeviceAuthorization{
		DeviceAuthID: deviceAuthID,
		UserCode:     userCode,
		Interval:     fmt.Sprintf("%d", codexIssuerDeviceCodePollIn),
	}, nil
}

func (s *codexAuthIssuerState) pollDeviceAuthorization(deviceAuthID string, userCode string) (*CodexDeviceAuthorizationExchange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)
	record, ok := s.deviceCodes[strings.TrimSpace(deviceAuthID)]
	if !ok {
		return nil, ErrCodexDeviceCodeNotFound
	}
	if !strings.EqualFold(strings.TrimSpace(record.UserCode), strings.TrimSpace(userCode)) {
		return nil, ErrCodexDeviceCodeNotFound
	}
	record.Polls++
	if !record.Approved || record.UserID == 0 {
		return nil, ErrCodexDeviceCodePending
	}

	if _, ok := s.authCodes[record.AuthorizationCode]; !ok {
		s.authCodes[record.AuthorizationCode] = &codexAuthCodeRecord{
			Code:          record.AuthorizationCode,
			UserID:        record.UserID,
			CodeChallenge: record.CodeChallenge,
			CreatedAt:     now,
		}
	}

	return &CodexDeviceAuthorizationExchange{
		AuthorizationCode: record.AuthorizationCode,
		CodeChallenge:     record.CodeChallenge,
		CodeVerifier:      record.CodeVerifier,
	}, nil
}

func (s *codexAuthIssuerState) approveDeviceCode(userCode string, userID int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)
	normalized := strings.ToUpper(strings.TrimSpace(userCode))
	if normalized == "" {
		return false, nil
	}
	for _, record := range s.deviceCodes {
		if strings.ToUpper(record.UserCode) != normalized {
			continue
		}
		record.Approved = true
		record.UserID = userID
		s.authCodes[record.AuthorizationCode] = &codexAuthCodeRecord{
			Code:          record.AuthorizationCode,
			UserID:        userID,
			CodeChallenge: record.CodeChallenge,
			CreatedAt:     now,
		}
		return true, nil
	}
	return false, nil
}

func (s *codexAuthIssuerState) listDeviceCodes() []CodexDeviceCodeView {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)
	views := make([]CodexDeviceCodeView, 0, len(s.deviceCodes))
	for _, record := range s.deviceCodes {
		views = append(views, CodexDeviceCodeView{
			DeviceAuthID: record.DeviceAuthID,
			UserCode:     record.UserCode,
			Approved:     record.Approved,
			Polls:        record.Polls,
			CreatedAt:    record.CreatedAt,
		})
	}
	sort.Slice(views, func(i int, j int) bool {
		return views[i].CreatedAt.After(views[j].CreatedAt)
	})
	return views
}

func (s *codexAuthIssuerState) cleanupLocked(now time.Time) {
	for code, record := range s.authCodes {
		if now.Sub(record.CreatedAt) > codexIssuerAuthCodeTTL {
			delete(s.authCodes, code)
		}
	}
	for id, record := range s.deviceCodes {
		if now.Sub(record.CreatedAt) > codexIssuerDeviceCodeTTL {
			delete(s.deviceCodes, id)
			delete(s.authCodes, record.AuthorizationCode)
		}
	}
}

func buildCodexIssuedTokens(user *model.User) (*CodexIssuedTokens, error) {
	idToken, err := buildCodexJWT(user, true)
	if err != nil {
		return nil, err
	}
	accessToken, err := buildCodexJWT(user, false)
	if err != nil {
		return nil, err
	}
	refreshToken, err := issueCodexRefreshToken(user.Id)
	if err != nil {
		return nil, err
	}
	return &CodexIssuedTokens{
		IDToken:      idToken,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(codexIssuerAccessTokenTTL.Seconds()),
		Scope:        codexIssuerScope,
		TokenType:    "Bearer",
	}, nil
}

func buildCodexJWT(user *model.User, idToken bool) (string, error) {
	headerSegment, err := jwtSegment(map[string]any{
		"alg": "none",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	email := strings.TrimSpace(user.Email)
	if email == "" {
		email = fmt.Sprintf("%s@local.new-api", strings.TrimSpace(user.Username))
	}

	now := time.Now()
	payload := map[string]any{
		"sub":   fmt.Sprintf("new-api-user-%d", user.Id),
		"iat":   now.Unix(),
		"exp":   now.Add(codexIssuerAccessTokenTTL).Unix(),
		"email": email,
		"https://api.openai.com/profile": map[string]any{
			"email": email,
		},
		"https://api.openai.com/auth": buildCodexAuthClaims(user),
	}
	if !idToken {
		jti, err := common.GenerateRandomCharsKey(24)
		if err != nil {
			return "", err
		}
		payload["jti"] = jti
	}

	payloadSegment, err := jwtSegment(payload)
	if err != nil {
		return "", err
	}
	signatureSegment := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return headerSegment + "." + payloadSegment + "." + signatureSegment, nil
}

func buildCodexAuthClaims(user *model.User) map[string]any {
	accountID := CodexAccountIDForUserID(user.Id)
	return map[string]any{
		"chatgpt_plan_type":             codexIssuerPlanType,
		"chatgpt_user_id":               fmt.Sprintf("new-api-user-%d", user.Id),
		"chatgpt_account_id":            accountID,
		"organization_id":               accountID,
		"project_id":                    "new-api",
		"completed_platform_onboarding": true,
		"is_org_owner":                  true,
	}
}

func jwtSegment(v any) (string, error) {
	b, err := common.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func issueCodexRefreshToken(userID int) (string, error) {
	payload := codexRefreshTokenPayload{
		Type:      "refresh_token",
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(codexIssuerRefreshTokenTTL).Unix(),
	}
	b, err := common.Marshal(payload)
	if err != nil {
		return "", err
	}
	segment := base64.RawURLEncoding.EncodeToString(b)
	return "rt_" + segment + "." + signCodexRefreshToken(segment), nil
}

func parseCodexRefreshToken(token string) (int, error) {
	trimmed := strings.TrimSpace(token)
	if !strings.HasPrefix(trimmed, "rt_") {
		return 0, ErrCodexRefreshTokenInvalid
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "rt_"), ".", 2)
	if len(parts) != 2 {
		return 0, ErrCodexRefreshTokenInvalid
	}
	if !hmac.Equal([]byte(signCodexRefreshToken(parts[0])), []byte(parts[1])) {
		return 0, ErrCodexRefreshTokenInvalid
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, ErrCodexRefreshTokenInvalid
	}
	var payload codexRefreshTokenPayload
	if err = common.Unmarshal(payloadBytes, &payload); err != nil {
		return 0, ErrCodexRefreshTokenInvalid
	}
	if payload.Type != "refresh_token" || payload.UserID <= 0 {
		return 0, ErrCodexRefreshTokenInvalid
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return 0, ErrCodexRefreshTokenExpired
	}
	return payload.UserID, nil
}

func issueCodexAPIToken(userID int) (string, error) {
	payload := codexRefreshTokenPayload{
		Type:      "api_token",
		UserID:    userID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(codexIssuerAccessTokenTTL).Unix(),
	}
	b, err := common.Marshal(payload)
	if err != nil {
		return "", err
	}
	segment := base64.RawURLEncoding.EncodeToString(b)
	return "atk_" + segment + "." + signCodexRefreshToken(segment), nil
}

func extractCodexUserIDFromAccessToken(token string) (int, error) {
	userID, _, _, err := extractCodexAccessTokenClaims(token)
	return userID, err
}

func extractCodexAccessTokenClaims(token string) (int, string, int64, error) {
	claims, err := parseJWTClaims(token)
	if err != nil {
		return 0, "", 0, err
	}

	sub, _ := claims["sub"].(string)
	sub = strings.TrimSpace(sub)
	var userID int
	if strings.HasPrefix(sub, "new-api-user-") {
		_, scanErr := fmt.Sscanf(sub, "new-api-user-%d", &userID)
		if scanErr == nil && userID > 0 {
			accountID, accountErr := extractCodexAccountIDFromClaims(claims)
			if accountErr != nil {
				return 0, "", 0, accountErr
			}
			expiresAt, expErr := extractJWTExpiresAt(claims)
			if expErr != nil {
				return 0, "", 0, expErr
			}
			return userID, accountID, expiresAt, nil
		}
	}

	rawAuth, ok := claims["https://api.openai.com/auth"].(map[string]any)
	if !ok {
		return 0, "", 0, errors.New("missing auth claims")
	}
	rawUserID, _ := rawAuth["chatgpt_user_id"].(string)
	rawUserID = strings.TrimSpace(rawUserID)
	if !strings.HasPrefix(rawUserID, "new-api-user-") {
		return 0, "", 0, errors.New("invalid auth claims")
	}
	if _, err = fmt.Sscanf(rawUserID, "new-api-user-%d", &userID); err != nil || userID <= 0 {
		return 0, "", 0, errors.New("invalid user id")
	}
	accountID, err := extractCodexAccountIDFromClaims(claims)
	if err != nil {
		return 0, "", 0, err
	}
	expiresAt, err := extractJWTExpiresAt(claims)
	if err != nil {
		return 0, "", 0, err
	}
	return userID, accountID, expiresAt, nil
}

func parseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err = common.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func extractCodexAccountIDFromClaims(claims map[string]any) (string, error) {
	rawAuth, ok := claims["https://api.openai.com/auth"].(map[string]any)
	if !ok {
		return "", errors.New("missing auth claims")
	}
	accountID, _ := rawAuth["chatgpt_account_id"].(string)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", errors.New("missing account id")
	}
	return accountID, nil
}

func extractJWTExpiresAt(claims map[string]any) (int64, error) {
	rawExp, ok := claims["exp"]
	if !ok {
		return 0, errors.New("missing exp")
	}
	switch value := rawExp.(type) {
	case float64:
		return int64(value), nil
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	default:
		return 0, errors.New("invalid exp")
	}
}

func signCodexRefreshToken(segment string) string {
	mac := hmac.New(sha256.New, []byte(common.SessionSecret))
	mac.Write([]byte(segment))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyCodeChallenge(codeChallenge string, codeVerifier string) bool {
	challenge := strings.TrimSpace(codeChallenge)
	if challenge == "" {
		return true
	}
	verifier := strings.TrimSpace(codeVerifier)
	if verifier == "" {
		return false
	}
	return pkceCodeChallenge(verifier) == challenge
}

func pkceCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(prefix string, length int) (string, error) {
	value, err := common.GenerateRandomCharsKey(length)
	if err != nil {
		return "", err
	}
	return prefix + "-" + value, nil
}

func randomUserCode() (string, error) {
	value, err := common.GenerateRandomCharsKey(8)
	if err != nil {
		return "", err
	}
	value = strings.ToUpper(value)
	return value[:4] + "-" + value[4:], nil
}
