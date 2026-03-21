package router

import (
	"embed"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

func SetWebRouter(router *gin.Engine, buildFS embed.FS, indexPage []byte) {
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	router.Use(middleware.DecompressRequestMiddleware())
	router.Use(middleware.GlobalWebRateLimit())
	router.Use(middleware.Cache())
	webRoute := router.Group("/")
	webRoute.Use(middleware.RouteTag("web"))
	{
		webRoute.GET("/oauth/authorize", controller.CodexIssuerAuthorize)
		webRoute.POST("/oauth/authorize", controller.CodexIssuerAuthorizeDecision)
		webRoute.POST("/oauth/login", controller.CodexIssuerBrowserLogin)
		webRoute.POST("/oauth/token", controller.CodexIssuerToken)
		webRoute.POST("/api/accounts/deviceauth/usercode", controller.CodexIssuerCreateDeviceCode)
		webRoute.POST("/api/accounts/deviceauth/token", controller.CodexIssuerPollDeviceCode)
		webRoute.GET("/codex/device", controller.CodexIssuerDevicePage)
		webRoute.POST("/codex/device", controller.CodexIssuerApproveDeviceCode)
		webRoute.GET("/api/codex/usage", controller.CodexBackendUsage)
		webRoute.GET("/backend-api/codex/models", controller.CodexBackendModels)
		webRoute.GET("/backend-api/wham/usage", controller.CodexBackendUsage)
		webRoute.GET("/backend-api/codex/responses", controller.CodexBackendResponses)
		webRoute.POST("/backend-api/codex/responses", controller.CodexBackendResponses)
		webRoute.POST("/backend-api/codex/responses/compact", controller.CodexBackendResponsesCompact)
	}
	router.Use(static.Serve("/", common.EmbedFolder(buildFS, "web/dist")))
	router.NoRoute(func(c *gin.Context) {
		c.Set(middleware.RouteTagKey, "web")
		if strings.HasPrefix(c.Request.RequestURI, "/backend-api/wham/") || strings.HasPrefix(c.Request.RequestURI, "/backend-api/codex/") {
			controller.CodexBackendPrefixNotFound(c)
			return
		}
		if strings.HasPrefix(c.Request.RequestURI, "/v1") || strings.HasPrefix(c.Request.RequestURI, "/api") || strings.HasPrefix(c.Request.RequestURI, "/assets") || strings.HasPrefix(c.Request.RequestURI, "/backend-api") {
			controller.RelayNotFound(c)
			return
		}
		c.Header("Cache-Control", "no-cache")
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexPage)
	})
}
