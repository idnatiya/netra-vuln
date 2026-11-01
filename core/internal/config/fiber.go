package config

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/model"
)

func NewFiber(config *viper.Viper, log *logrus.Logger) *fiber.App {
	cfg := fiber.Config{
		AppName:      config.GetString("app.name"),
		ErrorHandler: NewErrorHandler(log),
		BodyLimit:    middleware.MaxReportBytes,
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}
	// TrustProxy makes ctx.IP() use X-Forwarded-For from private-network proxies
	// (the reverse proxy in front). Leave false when clients connect directly.
	if config.GetBool("web.trust_proxy") {
		cfg.TrustProxy = true
		cfg.ProxyHeader = fiber.HeaderXForwardedFor
		cfg.TrustProxyConfig = fiber.TrustProxyConfig{Private: true, Loopback: true}
	}
	return fiber.New(cfg)
}

// NewErrorHandler turns errors into status codes. Admin API errors use the
// WebResponse envelope; agent API errors stay plain text. The agent drops a
// report on 400/413/422 and retries everything else, so only payload problems
// are 4xx-final.
func NewErrorHandler(log *logrus.Logger) fiber.ErrorHandler {
	return func(ctx fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		msg := err.Error()
		var fe *fiber.Error
		if errors.As(err, &fe) {
			code, msg = fe.Code, fe.Message
		}
		fields := logrus.Fields{"path": ctx.Path(), "status": code, "remote": ctx.IP()}
		if code >= 500 {
			log.WithFields(fields).WithError(err).Error("Request failed")
			msg = "internal server error"
		} else {
			log.WithFields(fields).Warn("Request rejected: " + msg)
		}
		if strings.HasPrefix(ctx.Path(), "/api/admin/") {
			return ctx.Status(code).JSON(model.WebResponse[any]{Errors: msg})
		}
		return ctx.Status(code).SendString(msg)
	}
}
