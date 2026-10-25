// Package httpapi exposes the agent-facing HTTP API on Fiber v3.
//
// Fasthttp reuses request buffers after a handler returns. Everything taken
// from a request is copied out (JSON is decoded into structs, the token is used
// only within the request), so the Immutable setting is not needed.
package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"

	"netra-vuln/central/internal/domain"
)

const (
	maxReportBytes = 20 << 20 // compressed (BodyLimit) and decompressed
	maxSmallBytes  = 64 << 10
	hostKey        = "host"
)

// Agent is what the handlers need from usecase.Agent (consumer-side interface).
type Agent interface {
	Authenticate(ctx context.Context, token string) (domain.Host, error)
	Heartbeat(ctx context.Context, h domain.Host, clientName, hostname string, meta domain.HostMeta) error
	Ingest(ctx context.Context, h domain.Host, r domain.Report) error
	ScanConfig(ctx context.Context, h domain.Host) ([]byte, error)
	Ping(ctx context.Context) error
}

type Enroller interface {
	Run(ctx context.Context, req domain.EnrollRequest) (string, error)
}

// Limits are sliding-window request caps per Window.
type Limits struct {
	Window     time.Duration
	PerHostMax int // per authenticated host
	// Global caps for unauthenticated work (enroll, token lookups).
	// ponytail: global because behind Caddy every request comes from the proxy IP;
	// switch to per-IP via a trusted X-Forwarded-For if abuse ever shows up.
	EnrollMax int
	AuthMax   int
}

func DefaultLimits() Limits {
	return Limits{Window: time.Minute, PerHostMax: 60, EnrollMax: 30, AuthMax: 300}
}

type Server struct {
	agent  Agent
	enroll Enroller
	log    *slog.Logger
	app    *fiber.App
}

func New(agent Agent, enroll Enroller, log *slog.Logger, limits Limits) *Server {
	s := &Server{agent: agent, enroll: enroll, log: log}
	s.app = fiber.New(fiber.Config{
		AppName:      "central",
		BodyLimit:    maxReportBytes,
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  2 * time.Minute,
		ErrorHandler: s.errorHandler,
	})

	s.app.Get("/healthz", s.healthz)
	s.app.Post("/api/v1/enroll", rateLimit(limits.EnrollMax, limits.Window, constKey("enroll")), s.handleEnroll)

	authed := s.app.Group("/api/v1",
		rateLimit(limits.AuthMax, limits.Window, constKey("auth")),
		s.authenticate,
		rateLimit(limits.PerHostMax, limits.Window, func(c fiber.Ctx) string {
			return strconv.FormatInt(fiber.Locals[domain.Host](c, hostKey).ID, 10)
		}))
	authed.Post("/heartbeat", s.handleHeartbeat)
	authed.Get("/config", s.handleConfig)
	authed.Post("/report", s.handleReport)
	return s
}

func (s *Server) App() *fiber.App { return s.app }

func rateLimit(max int, window time.Duration, key func(fiber.Ctx) string) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        window,
		KeyGenerator:      key,
		LimiterMiddleware: limiter.SlidingWindow{},
	})
}

func constKey(k string) func(fiber.Ctx) string { return func(fiber.Ctx) string { return k } }

func (s *Server) healthz(c fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()
	if err := s.agent.Ping(ctx); err != nil {
		s.log.Error("healthz: database unreachable", "err", err)
		return c.Status(fiber.StatusServiceUnavailable).SendString("database unreachable")
	}
	return c.SendString("ok\n")
}

func (s *Server) authenticate(c fiber.Ctx) error {
	token, _ := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	h, err := s.agent.Authenticate(c.Context(), token)
	if err != nil {
		return err
	}
	fiber.Locals[domain.Host](c, hostKey, h)
	return c.Next()
}

func smallBody(c fiber.Ctx) ([]byte, error) {
	b := c.BodyRaw()
	if len(b) > maxSmallBytes {
		return nil, fiber.ErrRequestEntityTooLarge
	}
	return b, nil
}

func (s *Server) handleEnroll(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	req, err := decodeEnroll(body)
	if err != nil {
		return err
	}
	token, err := s.enroll.Run(c.Context(), req)
	if err != nil {
		return err
	}
	s.log.Info("host enrolled", "client", req.ClientName, "hostname", req.Hostname, "remote", c.IP())
	return c.JSON(enrollResponse(token))
}

func (s *Server) handleHeartbeat(c fiber.Ctx) error {
	body, err := smallBody(c)
	if err != nil {
		return err
	}
	clientName, hostname, meta, err := decodeHeartbeat(body)
	if err != nil {
		return err
	}
	h := fiber.Locals[domain.Host](c, hostKey)
	if err := s.agent.Heartbeat(c.Context(), h, clientName, hostname, meta); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (s *Server) handleConfig(c fiber.Ctx) error {
	raw, err := s.agent.ScanConfig(c.Context(), fiber.Locals[domain.Host](c, hostKey))
	if err != nil {
		return err
	}
	cfg, err := encodeScanConfig(raw)
	if err != nil {
		return err
	}
	return c.JSON(cfg)
}

func (s *Server) handleReport(c fiber.Ctx) error {
	body, err := reportBody(c)
	if err != nil {
		return err
	}
	rep, err := decodeReport(body)
	if err != nil {
		return err
	}
	h := fiber.Locals[domain.Host](c, hostKey)
	if err := s.agent.Ingest(c.Context(), h, rep); err != nil {
		return err
	}
	s.log.Info("report ingested", "client", h.ClientName, "hostname", h.Hostname,
		"status", rep.Status, "findings", len(rep.Findings))
	return c.SendStatus(fiber.StatusNoContent)
}

// reportBody gunzips explicitly instead of using c.Body(): on a decode failure
// c.Body() returns the error text as the body and only sets the response
// status, which the handler would then overwrite.
func reportBody(c fiber.Ctx) ([]byte, error) {
	raw := c.BodyRaw() // already capped at BodyLimit by fasthttp
	switch strings.ToLower(c.Get(fiber.HeaderContentEncoding)) {
	case "", "identity":
		return raw, nil
	case "gzip":
	default:
		return nil, fiber.ErrUnsupportedMediaType
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", domain.ErrInvalid, err)
	}
	defer zr.Close()
	b, err := io.ReadAll(&limitReader{r: zr, n: maxReportBytes})
	if err != nil && !errors.Is(err, errTooLarge) {
		err = fmt.Errorf("%w: gzip: %v", domain.ErrInvalid, err)
	}
	return b, err
}

// errorHandler maps errors to status codes. The agent drops a report on
// 400/413/422 and retries everything else, so only payload problems are 4xx-final.
func (s *Server) errorHandler(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	var fe *fiber.Error
	switch {
	case errors.As(err, &fe):
		code = fe.Code
	case errors.Is(err, errTooLarge):
		code = fiber.StatusRequestEntityTooLarge
	case errors.Is(err, domain.ErrInvalid):
		code = fiber.StatusBadRequest
	case errors.Is(err, domain.ErrUnauthorized):
		code = fiber.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		code = fiber.StatusForbidden
	case errors.Is(err, domain.ErrConflict):
		code = fiber.StatusConflict
	}
	msg := err.Error()
	if code >= 500 {
		s.log.Error("request failed", "path", c.Path(), "err", err)
		msg = "internal server error"
	} else {
		s.log.Warn("request rejected", "path", c.Path(), "status", code, "err", err, "remote", c.IP())
	}
	return c.Status(code).SendString(msg)
}

var errTooLarge = errors.New("decompressed body too large")

// limitReader fails (instead of silently truncating like io.LimitReader) once
// more than n bytes are read.
type limitReader struct {
	r io.Reader
	n int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if l.n < 0 {
		return n, errTooLarge
	}
	return n, err
}
