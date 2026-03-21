package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	codexchannel "github.com/QuantumNous/new-api/relay/channel/codex"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type codexBackendAuthContext struct {
	UserID    int
	AccountID string
}

type codexBackendModelProbe struct {
	Model string `json:"model"`
}

func CodexBackendModels(c *gin.Context) {
	if _, ok := requireCodexBackendToken(c, false); !ok {
		return
	}

	models := make([]gin.H, 0, len(codexchannel.ModelList))
	for _, model := range codexchannel.ModelList {
		models = append(models, gin.H{
			"slug":                    model,
			"display_name":            model,
			"description":             "Codex model served by new-api",
			"default_reasoning_level": "medium",
			"supported_reasoning_levels": []gin.H{
				{"effort": "low", "description": "Fast responses with lighter reasoning"},
				{"effort": "medium", "description": "Balances speed and reasoning depth for everyday tasks"},
				{"effort": "high", "description": "Greater reasoning depth for complex problems"},
				{"effort": "xhigh", "description": "Extra high reasoning depth for complex problems"},
			},
			"visibility":        "list",
			"supported_in_api":  true,
			"support_verbosity": true,
			"default_verbosity": "low",
			"input_modalities":  []string{"text", "image"},
			"prefer_websockets": false,
		})
	}
	c.JSON(http.StatusOK, gin.H{"models": models})
}

func CodexBackendUsage(c *gin.Context) {
	auth, ok := requireCodexBackendToken(c, true)
	if !ok {
		return
	}

	usage, err := model.GetCodexSubscriptionRateLimitUsage(auth.UserID)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	planType := "plus"
	rateLimit := gin.H{
		"allowed":          false,
		"limit_reached":    true,
		"primary_window":   nil,
		"secondary_window": nil,
	}
	if usage != nil {
		planType = usage.PlanType
		rateLimit = gin.H{
			"allowed":          usage.Allowed,
			"limit_reached":    usage.LimitReached,
			"primary_window":   usage.PrimaryWindow,
			"secondary_window": usage.SecondaryWindow,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"plan_type":              planType,
		"rate_limit":             rateLimit,
		"additional_rate_limits": []any{},
		"account_id":             auth.AccountID,
	})
}

func CodexBackendResponses(c *gin.Context) {
	auth, ok := requireCodexBackendToken(c, true)
	if !ok {
		return
	}

	if c.Request.Method == http.MethodPost {
		if !prepareCodexBackendRelayContext(c, auth) {
			return
		}
		modelName, ok := prepareCodexBackendRelayModel(c, types.RelayFormatOpenAIResponses)
		if !ok {
			return
		}
		if !prepareCodexBackendRelayChannel(c, modelName) {
			return
		}
		originalPath := c.Request.URL.Path
		c.Request.URL.Path = "/pg/responses"
		defer func() {
			c.Request.URL.Path = originalPath
		}()
		Relay(c, types.RelayFormatOpenAIResponses)
		return
	}

	if websocket.IsWebSocketUpgrade(c.Request) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "websocket responses are not implemented"})
		return
	}

	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
}

func CodexBackendResponsesCompact(c *gin.Context) {
	auth, ok := requireCodexBackendToken(c, true)
	if !ok {
		return
	}
	if c.Request.Method != http.MethodPost {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
		return
	}
	if !prepareCodexBackendRelayContext(c, auth) {
		return
	}
	modelName, ok := prepareCodexBackendRelayModel(c, types.RelayFormatOpenAIResponsesCompaction)
	if !ok {
		return
	}
	if !prepareCodexBackendRelayChannel(c, modelName) {
		return
	}
	originalPath := c.Request.URL.Path
	c.Request.URL.Path = "/pg/responses/compact"
	defer func() {
		c.Request.URL.Path = originalPath
	}()
	Relay(c, types.RelayFormatOpenAIResponsesCompaction)
}

func CodexBackendPrefixNotFound(c *gin.Context) {
	requireAccountHeader := strings.HasPrefix(c.Request.URL.Path, "/backend-api/wham/")
	if _, ok := requireCodexBackendToken(c, requireAccountHeader); !ok {
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("unknown path: %s", c.Request.URL.Path)})
}

func requireCodexBackendToken(c *gin.Context, requireAccountHeader bool) (*codexBackendAuthContext, bool) {
	authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return nil, false
	}
	token := strings.TrimSpace(authHeader[7:])
	claims, err := service.ValidateCodexBackendToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid api token"})
		return nil, false
	}
	accountID := strings.TrimSpace(c.GetHeader("chatgpt-account-id"))
	if requireAccountHeader && accountID != claims.AccountID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "chatgpt-account-id mismatch"})
		return nil, false
	}
	return &codexBackendAuthContext{
		UserID:    claims.UserID,
		AccountID: claims.AccountID,
	}, true
}

func prepareCodexBackendRelayContext(c *gin.Context, auth *codexBackendAuthContext) bool {
	userCache, err := model.GetUserCache(auth.UserID)
	if err != nil {
		common.ApiError(c, err)
		return false
	}
	if userCache == nil || userCache.Status != common.UserStatusEnabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "user is disabled"})
		return false
	}

	userCache.WriteContext(c)
	c.Set("id", auth.UserID)
	common.SetContextKey(c, constant.ContextKeyUsingGroup, userCache.Group)

	userSetting := userCache.GetSetting()
	userSetting.BillingPreference = "subscription_only"
	common.SetContextKey(c, constant.ContextKeyUserSetting, userSetting)
	return true
}

func prepareCodexBackendRelayModel(c *gin.Context, relayFormat types.RelayFormat) (string, bool) {
	probe := &codexBackendModelProbe{}
	if err := common.UnmarshalBodyReusable(c, probe); err != nil {
		logger.LogError(c, fmt.Sprintf(
			"codex backend request body parse failed: content_type=%q content_encoding=%q body_preview=%q err=%v",
			c.GetHeader("Content-Type"),
			c.GetHeader("Content-Encoding"),
			codexBackendBodyPreview(c),
			err,
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return "", false
	}

	modelName := strings.TrimSpace(probe.Model)
	switch relayFormat {
	case types.RelayFormatOpenAIResponsesCompaction:
		if modelName != "" {
			modelName = ratio_setting.WithCompactModelSuffix(modelName)
		}
	}
	if modelName == "" {
		logger.LogError(c, fmt.Sprintf(
			"codex backend request missing model: content_type=%q body_preview=%q",
			c.GetHeader("Content-Type"),
			codexBackendBodyPreview(c),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "model is required"})
		return "", false
	}
	c.Set("original_model", modelName)
	common.SetContextKey(c, constant.ContextKeyOriginalModel, modelName)
	return modelName, true
}

func codexBackendBodyPreview(c *gin.Context) string {
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		return fmt.Sprintf("<unavailable: %v>", err)
	}
	body, err := storage.Bytes()
	if err != nil {
		return fmt.Sprintf("<unavailable: %v>", err)
	}
	preview := strings.TrimSpace(string(body))
	if len(preview) > 1024 {
		preview = preview[:1024] + "...(truncated)"
	}
	return preview
}

func prepareCodexBackendRelayChannel(c *gin.Context, modelName string) bool {
	usingGroup := common.GetContextKeyString(c, constant.ContextKeyUsingGroup)
	if usingGroup == "" {
		usingGroup = "default"
		common.SetContextKey(c, constant.ContextKeyUsingGroup, usingGroup)
	}
	selectChannel := func(name string) (*model.Channel, error) {
		channel, _, err := service.CacheGetRandomSatisfiedChannel(&service.RetryParam{
			Ctx:        c,
			ModelName:  name,
			TokenGroup: usingGroup,
			Retry:      common.GetPointer(0),
		})
		return channel, err
	}

	channel, err := selectChannel(modelName)
	if (err != nil || channel == nil) && strings.HasSuffix(modelName, ratio_setting.CompactModelSuffix) {
		baseModelName := strings.TrimSuffix(modelName, ratio_setting.CompactModelSuffix)
		if baseModelName != "" {
			channel, err = selectChannel(baseModelName)
		}
	}

	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("failed to select channel for model %s: %v", modelName, err)})
		return false
	}
	if channel == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("no available channel for model %s", modelName)})
		return false
	}
	common.SetContextKey(c, constant.ContextKeyRequestStartTime, time.Now())
	if newAPIError := middleware.SetupContextForSelectedChannel(c, channel, modelName); newAPIError != nil {
		c.JSON(newAPIError.StatusCode, gin.H{"error": newAPIError.Error()})
		return false
	}
	return true
}
