// Package middleware holds the Fiber middleware for the agent and admin APIs.
//
// Fasthttp reuses request buffers after a handler returns. Everything taken
// from a request is copied out (JSON is decoded into structs, tokens are used
// only within the request), so the Immutable setting is not needed.
package middleware

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

const (
	// MaxReportBytes caps a report, compressed (Fiber BodyLimit) and decompressed.
	MaxReportBytes = 20 << 20
	// MaxSmallBytes caps every other request body.
	MaxSmallBytes = 64 << 10

	SessionCookie = "vuln_session"
	hostKey       = "host"
	authKey       = "auth"
	bodyKey       = "body"
)

// NewHostAuth authenticates an agent by its Bearer host token.
func NewHostAuth(agentUseCase *usecase.AgentUseCase) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		token, _ := strings.CutPrefix(ctx.Get(fiber.HeaderAuthorization), "Bearer ")
		host, err := agentUseCase.Verify(ctx.Context(), token)
		if err != nil {
			return err
		}
		ctx.Locals(hostKey, host)
		return ctx.Next()
	}
}

func GetHost(ctx fiber.Ctx) *entity.Host { return ctx.Locals(hostKey).(*entity.Host) }

// NewSessionAuth authenticates an admin by the session cookie.
func NewSessionAuth(authUseCase *usecase.AuthUseCase) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		auth, err := authUseCase.Verify(ctx.Context(), ctx.Cookies(SessionCookie))
		if err != nil {
			return err
		}
		ctx.Locals(authKey, auth)
		return ctx.Next()
	}
}

func GetAuth(ctx fiber.Ctx) *model.Auth { return ctx.Locals(authKey).(*model.Auth) }

// NewSameOrigin rejects cross-site state changes (CSRF defense on top of SameSite).
func NewSameOrigin() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		switch ctx.Method() {
		case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
			return ctx.Next()
		}
		u, err := url.Parse(ctx.Get(fiber.HeaderOrigin))
		if err != nil || u.Host == "" || u.Host != ctx.Host() {
			return fiber.NewError(fiber.StatusForbidden, "cross-origin request")
		}
		return ctx.Next()
	}
}

// NewRateLimit caps requests per key in a sliding window.
func NewRateLimit(max int, window time.Duration, key func(fiber.Ctx) string) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        window,
		KeyGenerator:      key,
		LimiterMiddleware: limiter.SlidingWindow{},
	})
}

func ConstKey(k string) func(fiber.Ctx) string { return func(fiber.Ctx) string { return k } }

func HostKey(ctx fiber.Ctx) string { return strconv.FormatInt(GetHost(ctx).ID, 10) }

func IPKey(prefix string) func(fiber.Ctx) string {
	return func(ctx fiber.Ctx) string { return prefix + ctx.IP() }
}

// NewSmallBody rejects bodies over MaxSmallBytes. Bodies are read with
// BodyRaw (never Body), see NewReportBody.
func NewSmallBody() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		if len(ctx.BodyRaw()) > MaxSmallBytes {
			return fiber.ErrRequestEntityTooLarge
		}
		return ctx.Next()
	}
}

// NewReportBody gunzips report bodies explicitly instead of using ctx.Body():
// on a decode failure ctx.Body() returns the error text as the body and only
// sets the response status, which the handler would then overwrite.
func NewReportBody() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		raw := ctx.BodyRaw() // already capped at BodyLimit by fasthttp
		switch strings.ToLower(ctx.Get(fiber.HeaderContentEncoding)) {
		case "", "identity":
			ctx.Locals(bodyKey, raw)
			return ctx.Next()
		case "gzip":
		default:
			return fiber.ErrUnsupportedMediaType
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "gzip: "+err.Error())
		}
		defer zr.Close()
		b, err := io.ReadAll(&limitReader{r: zr, n: MaxReportBytes})
		if errors.Is(err, errTooLarge) {
			return fiber.NewError(fiber.StatusRequestEntityTooLarge, errTooLarge.Error())
		}
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "gzip: "+err.Error())
		}
		ctx.Locals(bodyKey, b)
		return ctx.Next()
	}
}

// GetBody returns the (decompressed) body set by NewReportBody, else BodyRaw.
func GetBody(ctx fiber.Ctx) []byte {
	if b, ok := ctx.Locals(bodyKey).([]byte); ok {
		return b
	}
	return ctx.BodyRaw()
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

// NewMcpAuth authenticates an AI client by its Bearer MCP token.
func NewMcpAuth(mcpTokenUseCase *usecase.McpTokenUseCase) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		token, _ := strings.CutPrefix(ctx.Get(fiber.HeaderAuthorization), "Bearer ")
		auth, err := mcpTokenUseCase.Verify(ctx.Context(), token)
		if err != nil {
			return err
		}
		ctx.Locals(authKey, auth)
		ctx.SetContext(model.ContextWithAuth(ctx.Context(), auth))
		return ctx.Next()
	}
}

func UserKey(ctx fiber.Ctx) string { return "mcp:" + strconv.FormatInt(GetAuth(ctx).UserID, 10) }

// NewMcpRateLimit caps MCP calls per admin and logs when an AI client hits it
// (Retry-After is set by the limiter).
func NewMcpRateLimit(max int, window time.Duration, log *logrus.Logger) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        window,
		KeyGenerator:      UserKey,
		LimiterMiddleware: limiter.SlidingWindow{},
		LimitReached: func(ctx fiber.Ctx) error {
			auth := GetAuth(ctx)
			log.WithFields(logrus.Fields{"by": auth.Username, "token": auth.McpTokenName}).Warn("MCP rate limited")
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limited: wait for Retry-After seconds, then use page_size 100 and filters to make fewer calls")
		},
	})
}
