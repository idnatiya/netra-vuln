package middleware

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// NewSecurityHeaders sets the browser hardening headers on every response.
// HSTS only takes effect when the reverse proxy in front serves HTTPS.
func NewSecurityHeaders() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		ctx.Set(fiber.HeaderStrictTransportSecurity, "max-age=31536000; includeSubDomains")
		ctx.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		ctx.Set(fiber.HeaderXFrameOptions, "DENY")
		ctx.Set(fiber.HeaderReferrerPolicy, "no-referrer")
		// The SPA loads only its own assets; inline styles come from the UI library.
		ctx.Set(fiber.HeaderContentSecurityPolicy, "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		return ctx.Next()
	}
}

// ParseCIDRs reads a space- or comma-separated list of CIDRs. Empty = nil.
func ParseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", f, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// NewAllowCIDRs answers 403 to clients outside allow (the dashboard, admin API
// and MCP; agents are never restricted). An empty list allows everyone.
func NewAllowCIDRs(allow []netip.Prefix) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		if len(allow) == 0 {
			return ctx.Next()
		}
		if ip, err := netip.ParseAddr(ctx.IP()); err == nil {
			ip = ip.Unmap()
			for _, p := range allow {
				if p.Contains(ip) {
					return ctx.Next()
				}
			}
		}
		return fiber.NewError(fiber.StatusForbidden, "forbidden")
	}
}
