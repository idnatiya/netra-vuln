// Package route wires the controllers and middleware into the Fiber app.
package route

import (
	nethttp "net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/delivery/http"
	"netra-vuln/core/internal/delivery/http/middleware"
)

// Limits are sliding-window request caps per Window.
type Limits struct {
	Window     time.Duration
	PerHostMax int // per authenticated host
	// Global caps for unauthenticated work (enroll, token lookups).
	// ponytail: global because behind a reverse proxy every request may come from the proxy IP;
	// switch to per-IP via a trusted X-Forwarded-For if abuse ever shows up.
	EnrollMax int
	AuthMax   int
	LoginMax  int // dashboard logins and password changes per client IP
	// MCP calls per admin, and in total; separate from the agent limits so a
	// busy AI client never throttles agents. 0 = 600.
	McpMax int
}

func DefaultLimits() Limits {
	return Limits{Window: time.Minute, PerHostMax: 60, EnrollMax: 30, AuthMax: 300, LoginMax: 10, McpMax: 600}
}

type RouteConfig struct {
	App                 *fiber.App
	Limits              Limits
	AgentController     *http.AgentController
	AuthController      *http.AuthController
	ClientController    *http.ClientController
	HostController      *http.HostController
	FindingController   *http.FindingController
	DashboardController *http.DashboardController
	InstallController   *http.InstallController
	McpTokenController  *http.McpTokenController
	McpHandler          nethttp.Handler
	HostAuthMiddleware  fiber.Handler
	AuthMiddleware      fiber.Handler
	McpAuthMiddleware   fiber.Handler
	AdminAllow          fiber.Handler // ADMIN_ALLOW_CIDRS: dashboard, admin API, MCP
	DashboardDir        string        // built SPA; empty = not served (dev uses Vite)
	Log                 *logrus.Logger
}

func (c *RouteConfig) Setup() {
	c.App.Use(middleware.NewSecurityHeaders())
	c.SetupAgentRoute()
	c.SetupAdminGuestRoute()
	c.SetupAdminAuthRoute()
	c.SetupMcpRoute()
	c.SetupDashboard() // last: its catch-all serves index.html for SPA routes
}

// SetupDashboard serves the built SPA, falling back to index.html for client routes.
func (c *RouteConfig) SetupDashboard() {
	if c.DashboardDir == "" {
		return
	}
	index := filepath.Join(c.DashboardDir, "index.html")
	c.App.Get("/*", c.AdminAllow, static.New(c.DashboardDir, static.Config{
		ModifyResponse: func(ctx fiber.Ctx) error {
			if strings.HasPrefix(ctx.Path(), "/assets/") { // hashed file names
				ctx.Set(fiber.HeaderCacheControl, "public, max-age=31536000, immutable")
			}
			return nil
		},
		NotFoundHandler: func(ctx fiber.Ctx) error {
			if strings.HasPrefix(ctx.Path(), "/api/") {
				return fiber.ErrNotFound
			}
			return ctx.Status(fiber.StatusOK).SendFile(index)
		},
	}))
}

// SetupMcpRoute is the MCP endpoint for AI clients (Bearer MCP token, read-only tools).
func (c *RouteConfig) SetupMcpRoute() {
	l := c.Limits
	mcpMax := l.McpMax
	if mcpMax == 0 {
		mcpMax = 600
	}
	c.App.All("/mcp", c.AdminAllow, middleware.NewRateLimit(mcpMax, l.Window, middleware.ConstKey("mcp")),
		middleware.NewSmallBody(), c.McpAuthMiddleware,
		middleware.NewMcpRateLimit(mcpMax, l.Window, c.Log),
		adaptor.HTTPHandlerWithContext(c.McpHandler))
}

// SetupAgentRoute is the API the agents push to (/api/v1, pkg/wire payloads).
func (c *RouteConfig) SetupAgentRoute() {
	l := c.Limits
	c.App.Get("/healthz", c.AgentController.Health)
	c.App.Get("/install.sh", middleware.NewRateLimit(l.AuthMax, l.Window, middleware.ConstKey("auth")), c.InstallController.Script)
	c.App.Post("/api/v1/enroll", middleware.NewRateLimit(l.EnrollMax, l.Window, middleware.ConstKey("enroll")),
		middleware.NewSmallBody(), c.AgentController.Enroll)

	agent := c.App.Group("/api/v1",
		middleware.NewRateLimit(l.AuthMax, l.Window, middleware.ConstKey("auth")),
		c.HostAuthMiddleware,
		middleware.NewRateLimit(l.PerHostMax, l.Window, middleware.HostKey))
	agent.Post("/heartbeat", middleware.NewSmallBody(), c.AgentController.Heartbeat)
	agent.Get("/config", c.AgentController.Config)
	agent.Post("/report", middleware.NewReportBody(), c.AgentController.Report)
}

// SetupAdminGuestRoute is the dashboard API reachable without a session.
func (c *RouteConfig) SetupAdminGuestRoute() {
	admin := c.App.Group("/api/admin/v1", c.AdminAllow, middleware.NewSameOrigin(), middleware.NewSmallBody())
	admin.Post("/login", middleware.NewRateLimit(c.Limits.LoginMax, time.Minute, middleware.IPKey("login:")), c.AuthController.Login)
	admin.Post("/logout", c.AuthController.Logout)
}

// SetupAdminAuthRoute is the dashboard API behind the session cookie.
func (c *RouteConfig) SetupAdminAuthRoute() {
	admin := c.App.Group("/api/admin/v1", c.AdminAllow, middleware.NewSameOrigin(), middleware.NewSmallBody(), c.AuthMiddleware)
	admin.Get("/me", c.AuthController.Current)
	admin.Post("/me/password", middleware.NewRateLimit(c.Limits.LoginMax, time.Minute, middleware.IPKey("password:")),
		c.AuthController.ChangePassword)
	admin.Get("/me/sessions", c.AuthController.Sessions)
	admin.Delete("/me/sessions", c.AuthController.RevokeOtherSessions)
	admin.Delete("/me/sessions/:id", c.AuthController.RevokeSession)

	admin.Get("/overview", c.DashboardController.Overview)
	admin.Get("/trend", c.DashboardController.Trend)
	admin.Get("/oldest-cves", c.DashboardController.OldestCVEs)
	admin.Get("/distribution", c.DashboardController.Distribution)

	admin.Get("/clients", c.ClientController.List)
	admin.Post("/clients", c.ClientController.Create)
	admin.Delete("/clients/:name", c.ClientController.Delete)
	admin.Put("/clients/:name/scan-config", c.ClientController.SetScanConfig)
	admin.Delete("/clients/:name/scan-config", c.ClientController.ClearScanConfig)
	admin.Post("/clients/:name/enroll-token", c.ClientController.IssueEnrollToken)
	admin.Get("/install", c.InstallController.Get)

	admin.Get("/hosts", c.HostController.List)
	admin.Post("/hosts/:id/revoke", c.HostController.Revoke)
	admin.Delete("/hosts/:id", c.HostController.Delete)

	admin.Get("/findings", c.FindingController.List)
	admin.Get("/components", c.FindingController.Components)
	admin.Post("/components/triage", c.FindingController.TriageComponent)
	admin.Patch("/findings/:id", c.FindingController.Triage)

	admin.Get("/mcp-tokens", c.McpTokenController.List)
	admin.Post("/mcp-tokens", c.McpTokenController.Create)
	admin.Delete("/mcp-tokens/:id", c.McpTokenController.Revoke)
}
