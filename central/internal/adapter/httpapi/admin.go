package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/domain"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
)

const (
	sessionCookie = "vuln_session"
	sessionKey    = "session"
	adminPrefix   = "/api/admin/v1"
)

// AdminAuth is what the admin routes need from usecase.AdminAuth.
type AdminAuth interface {
	Login(ctx context.Context, username, password string) (string, domain.Session, error)
	Session(ctx context.Context, token string) (domain.Session, error)
	Logout(ctx context.Context, token string) error
}

// Dashboard is what the admin routes need from usecase.Dashboard.
type Dashboard interface {
	Overview(ctx context.Context, clientName string) (domain.Overview, error)
	Clients(ctx context.Context) ([]domain.ClientRow, error)
	Hosts(ctx context.Context, clientName string) ([]domain.HostRow, error)
	Findings(ctx context.Context, f domain.FindingFilter) (domain.Page[domain.FindingRow], error)
	Components(ctx context.Context, f domain.FindingFilter) ([]domain.ComponentRow, error)
	Trend(ctx context.Context, clientName string, hostID int64, days int) ([]domain.TrendPoint, error)
	OldestCVEs(ctx context.Context, clientName string, limit int) ([]domain.CVEAge, error)
	Distribution(ctx context.Context) (domain.Distribution, error)
	TriageFinding(ctx context.Context, id int64, status domain.TriageStatus, note string) error
	TriageComponent(ctx context.Context, hostID int64, kind domain.ComponentKind, component string,
		status domain.TriageStatus, note string) (int, error)
	RevokeHost(ctx context.Context, id int64) (domain.Host, error)
	CreateClient(ctx context.Context, name string) (string, error)
	SetScanConfig(ctx context.Context, clientName string, cfg []byte) error
}

// MountAdmin adds the dashboard API. Auth is a session cookie (HttpOnly, Secure,
// SameSite=Strict); state-changing requests must also carry a same-origin Origin.
func (s *Server) MountAdmin(auth AdminAuth, dash Dashboard) {
	a := &adminRoutes{auth: auth, dash: dash, s: s}
	g := s.app.Group(adminPrefix, sameOrigin)
	login := rateLimit(s.limits.LoginMax, time.Minute, func(c fiber.Ctx) string { return "login:" + c.IP() })
	need := a.requireSession

	g.Post("/login", login, a.login)
	g.Post("/logout", a.logout)
	g.Get("/me", need, a.me)
	g.Get("/overview", need, a.overview)
	g.Get("/clients", need, a.clients)
	g.Post("/clients", need, a.createClient)
	g.Put("/clients/:name/scan-config", need, a.setScanConfig)
	g.Delete("/clients/:name/scan-config", need, a.clearScanConfig)
	g.Get("/hosts", need, a.hosts)
	g.Post("/hosts/:id/revoke", need, a.revokeHost)
	g.Get("/findings", need, a.findings)
	g.Get("/components", need, a.components)
	g.Post("/components/triage", need, a.triageComponent)
	g.Patch("/findings/:id", need, a.triage)
	g.Get("/trend", need, a.trend)
	g.Get("/oldest-cves", need, a.oldestCVEs)
	g.Get("/distribution", need, a.distribution)
}

type adminRoutes struct {
	auth AdminAuth
	dash Dashboard
	s    *Server
}

// sameOrigin rejects cross-site state changes (CSRF defense on top of SameSite).
func sameOrigin(c fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return c.Next()
	}
	u, err := url.Parse(c.Get(fiber.HeaderOrigin))
	if err != nil || u.Host == "" || u.Host != c.Host() {
		return fmt.Errorf("%w: cross-origin request", domain.ErrForbidden)
	}
	return c.Next()
}

func (a *adminRoutes) requireSession(c fiber.Ctx) error {
	sess, err := a.auth.Session(c.Context(), c.Cookies(sessionCookie))
	if err != nil {
		return err
	}
	fiber.Locals[domain.Session](c, sessionKey, sess)
	return c.Next()
}

func setSessionCookie(c fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/api/admin",
		Expires:  expires,
		HTTPOnly: true,
		Secure:   true, // browsers also accept Secure cookies on http://localhost
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (a *adminRoutes) login(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	var req loginRequest
	if err := decodeJSON(body, &req); err != nil {
		return err
	}
	token, sess, err := a.auth.Login(c.Context(), req.Username, req.Password)
	if err != nil {
		a.s.log.Warn("admin login failed", "username", req.Username, "remote", c.IP())
		return err
	}
	a.s.log.Info("admin login", "username", sess.Username, "remote", c.IP())
	setSessionCookie(c, token, sess.ExpiresAt)
	return c.JSON(meResponse{Username: sess.Username, ExpiresAt: sess.ExpiresAt})
}

func (a *adminRoutes) logout(c fiber.Ctx) error {
	if err := a.auth.Logout(c.Context(), c.Cookies(sessionCookie)); err != nil {
		return err
	}
	setSessionCookie(c, "", time.Unix(0, 0))
	return c.SendStatus(fiber.StatusNoContent)
}

func (a *adminRoutes) me(c fiber.Ctx) error {
	sess := fiber.Locals[domain.Session](c, sessionKey)
	return c.JSON(meResponse{Username: sess.Username, ExpiresAt: sess.ExpiresAt})
}

func (a *adminRoutes) overview(c fiber.Ctx) error {
	ov, err := a.dash.Overview(c.Context(), c.Query("client"))
	if err != nil {
		return err
	}
	t := ov.Totals
	return c.JSON(overviewDTO{
		Totals: totalsDTO{Clients: t.Clients, Hosts: t.Hosts, OpenCritical: t.OpenCritical, OpenHigh: t.OpenHigh,
			Accepted: t.Accepted, FalsePositive: t.FalsePositive, StaleHosts: t.StaleHosts,
			RebootRequired: t.RebootRequired, AutoUpdateOff: t.AutoUpdateOff},
		Clients: toClientDTOs(ov.Clients),
	})
}

func (a *adminRoutes) clients(c fiber.Ctx) error {
	cs, err := a.dash.Clients(c.Context())
	if err != nil {
		return err
	}
	return c.JSON(toClientDTOs(cs))
}

func (a *adminRoutes) createClient(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	var req createClientRequest
	if err := decodeJSON(body, &req); err != nil {
		return err
	}
	token, err := a.dash.CreateClient(c.Context(), req.Name)
	if err != nil {
		return err
	}
	a.s.log.Info("client created", "client", req.Name, "by", fiber.Locals[domain.Session](c, sessionKey).Username)
	return c.Status(fiber.StatusCreated).JSON(createClientResponse{Name: req.Name, EnrollToken: token})
}

func (a *adminRoutes) setScanConfig(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	cfg, err := wire.ParseScanConfig(body)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrInvalid, err)
	}
	if err := a.dash.SetScanConfig(c.Context(), c.Params("name"), cfg); err != nil {
		return err
	}
	return c.Type("json").Send(cfg)
}

func (a *adminRoutes) clearScanConfig(c fiber.Ctx) error {
	if err := a.dash.SetScanConfig(c.Context(), c.Params("name"), nil); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (a *adminRoutes) hosts(c fiber.Ctx) error {
	hs, err := a.dash.Hosts(c.Context(), c.Query("client"))
	if err != nil {
		return err
	}
	return c.JSON(mapSlice(hs, toHostDTO))
}

func (a *adminRoutes) revokeHost(c fiber.Ctx) error {
	id, err := idParam(c)
	if err != nil {
		return err
	}
	h, err := a.dash.RevokeHost(c.Context(), id)
	if err != nil {
		return err
	}
	a.s.log.Info("host revoked", "client", h.ClientName, "hostname", h.Hostname,
		"by", fiber.Locals[domain.Session](c, sessionKey).Username)
	return c.SendStatus(fiber.StatusNoContent)
}

// findingFilter reads the filter query parameters shared by /findings and /components.
func findingFilter(c fiber.Ctx) (domain.FindingFilter, error) {
	f := domain.FindingFilter{
		Client:          c.Query("client"),
		Severity:        c.Query("severity"),
		Status:          domain.TriageStatus(c.Query("status")),
		Query:           c.Query("q"),
		ComponentKind:   domain.ComponentKind(c.Query("component_kind")),
		Component:       c.Query("component"),
		IncludeResolved: c.Query("include_resolved") == "true",
		Sort:            c.Query("sort"),
	}
	var err error
	f.HostID, err = intQuery(c, "host_id", 0)
	return f, err
}

func (a *adminRoutes) components(c fiber.Ctx) error {
	f, err := findingFilter(c)
	if err != nil {
		return err
	}
	rows, err := a.dash.Components(c.Context(), f)
	if err != nil {
		return err
	}
	return c.JSON(mapSlice(rows, toComponentDTO))
}

func (a *adminRoutes) findings(c fiber.Ctx) error {
	f, err := findingFilter(c)
	if err != nil {
		return err
	}
	page, err := intQuery(c, "page", 1)
	if err != nil {
		return err
	}
	size, err := intQuery(c, "page_size", 0)
	if err != nil {
		return err
	}
	f.Page, f.PageSize = int(page), int(size)
	if err := f.Normalize(); err != nil {
		return err
	}
	res, err := a.dash.Findings(c.Context(), f)
	if err != nil {
		return err
	}
	return c.JSON(pageDTO[findingDTO]{Items: mapSlice(res.Items, toFindingDTO), Total: res.Total,
		Page: f.Page, PageSize: f.PageSize})
}

func (a *adminRoutes) triage(c fiber.Ctx) error {
	id, err := idParam(c)
	if err != nil {
		return err
	}
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	var req triageRequest
	if err := decodeJSON(body, &req); err != nil {
		return err
	}
	if err := a.dash.TriageFinding(c.Context(), id, domain.TriageStatus(req.Status), req.Note); err != nil {
		return err
	}
	a.s.log.Info("finding triaged", "id", id, "status", req.Status,
		"by", fiber.Locals[domain.Session](c, sessionKey).Username)
	return c.SendStatus(fiber.StatusNoContent)
}

func (a *adminRoutes) triageComponent(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	var req componentTriageRequest
	if err := decodeJSON(body, &req); err != nil {
		return err
	}
	n, err := a.dash.TriageComponent(c.Context(), req.HostID, domain.ComponentKind(req.Kind), req.Key,
		domain.TriageStatus(req.Status), req.Note)
	if err != nil {
		return err
	}
	a.s.log.Info("component triaged", "host_id", req.HostID, "kind", req.Kind, "component", req.Key,
		"status", req.Status, "findings", n, "by", fiber.Locals[domain.Session](c, sessionKey).Username)
	return c.JSON(componentTriageResponse{Updated: n})
}

func (a *adminRoutes) trend(c fiber.Ctx) error {
	hostID, err := intQuery(c, "host_id", 0)
	if err != nil {
		return err
	}
	days, err := intQuery(c, "days", 30)
	if err != nil {
		return err
	}
	pts, err := a.dash.Trend(c.Context(), c.Query("client"), hostID, int(days))
	if err != nil {
		return err
	}
	return c.JSON(mapSlice(pts, func(p domain.TrendPoint) trendDTO {
		return trendDTO{Day: p.Day.Format(time.DateOnly), Critical: p.Critical, High: p.High}
	}))
}

func (a *adminRoutes) oldestCVEs(c fiber.Ctx) error {
	limit, err := intQuery(c, "limit", 20)
	if err != nil {
		return err
	}
	cves, err := a.dash.OldestCVEs(c.Context(), c.Query("client"), int(limit))
	if err != nil {
		return err
	}
	return c.JSON(mapSlice(cves, func(v domain.CVEAge) cveAgeDTO {
		return cveAgeDTO{CVE: v.CVE, Severity: v.Severity, Title: v.Title, FirstSeen: v.FirstSeen, Hosts: v.Hosts}
	}))
}

func (a *adminRoutes) distribution(c fiber.Ctx) error {
	d, err := a.dash.Distribution(c.Context())
	if err != nil {
		return err
	}
	return c.JSON(distributionDTO{OS: toCounts(d.OS), AgentVersions: toCounts(d.AgentVersions),
		TrivyVersions: toCounts(d.TrivyVersions)})
}

func idParam(c fiber.Ctx) (int64, error) {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, fmt.Errorf("%w: id %q", domain.ErrInvalid, c.Params("id"))
	}
	return id, nil
}

func intQuery(c fiber.Ctx, key string, def int64) (int64, error) {
	v := c.Query(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s %q", domain.ErrInvalid, key, v)
	}
	return n, nil
}
