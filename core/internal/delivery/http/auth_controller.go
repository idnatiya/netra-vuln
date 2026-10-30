package http

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

// AuthController handles dashboard login/logout and the signed-in admin's account.
type AuthController struct {
	Log     *logrus.Logger
	UseCase *usecase.AuthUseCase
}

func NewAuthController(useCase *usecase.AuthUseCase, logger *logrus.Logger) *AuthController {
	return &AuthController{Log: logger, UseCase: useCase}
}

func setSessionCookie(ctx fiber.Ctx, value string, expires time.Time) {
	ctx.Cookie(&fiber.Cookie{
		Name:     middleware.SessionCookie,
		Value:    value,
		Path:     "/api/admin",
		Expires:  expires,
		HTTPOnly: true,
		Secure:   true, // browsers also accept Secure cookies on http://localhost
		SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func (c *AuthController) Login(ctx fiber.Ctx) error {
	request := new(model.LoginUserRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	request.IP, request.UserAgent = ctx.IP(), ctx.Get(fiber.HeaderUserAgent)
	token, auth, err := c.UseCase.Login(ctx.Context(), request)
	if err != nil {
		c.Log.WithFields(logrus.Fields{"username": request.Username, "remote": ctx.IP()}).Warn("Admin login failed")
		return err
	}
	c.Log.WithFields(logrus.Fields{"username": auth.Username, "remote": ctx.IP()}).Info("Admin login")
	setSessionCookie(ctx, token, auth.ExpiresAt)
	return ctx.JSON(model.WebResponse[*model.MeResponse]{Data: &model.MeResponse{Username: auth.Username, ExpiresAt: auth.ExpiresAt}})
}

func (c *AuthController) Logout(ctx fiber.Ctx) error {
	if err := c.UseCase.Logout(ctx.Context(), ctx.Cookies(middleware.SessionCookie)); err != nil {
		return err
	}
	setSessionCookie(ctx, "", time.Unix(0, 0))
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *AuthController) Current(ctx fiber.Ctx) error {
	auth := middleware.GetAuth(ctx)
	return ctx.JSON(model.WebResponse[*model.MeResponse]{Data: &model.MeResponse{Username: auth.Username, ExpiresAt: auth.ExpiresAt}})
}

func (c *AuthController) ChangePassword(ctx fiber.Ctx) error {
	request := new(model.ChangePasswordRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	response, err := c.UseCase.ChangePassword(ctx.Context(), middleware.GetAuth(ctx), request)
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[*model.CountResponse]{Data: response})
}

func (c *AuthController) Sessions(ctx fiber.Ctx) error {
	response, err := c.UseCase.Sessions(ctx.Context(), middleware.GetAuth(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.SessionResponse]{Data: response})
}

func (c *AuthController) RevokeSession(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	if err := c.UseCase.RevokeSession(ctx.Context(), middleware.GetAuth(ctx), &model.RevokeSessionRequest{ID: id}); err != nil {
		return err
	}
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *AuthController) RevokeOtherSessions(ctx fiber.Ctx) error {
	response, err := c.UseCase.RevokeOtherSessions(ctx.Context(), middleware.GetAuth(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[*model.CountResponse]{Data: response})
}
