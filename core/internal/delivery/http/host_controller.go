package http

import (
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

type HostController struct {
	Log     *logrus.Logger
	UseCase *usecase.HostUseCase
}

func NewHostController(useCase *usecase.HostUseCase, logger *logrus.Logger) *HostController {
	return &HostController{Log: logger, UseCase: useCase}
}

func (c *HostController) List(ctx fiber.Ctx) error {
	response, err := c.UseCase.Search(ctx.Context(), &model.SearchHostRequest{Client: ctx.Query("client")})
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.HostResponse]{Data: response})
}

func (c *HostController) Revoke(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	host, err := c.UseCase.Revoke(ctx.Context(), &model.RevokeHostRequest{ID: id})
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"client": host.Client.Name, "hostname": host.Hostname,
		"by": middleware.GetAuth(ctx).Username}).Info("Host revoked")
	return ctx.SendStatus(fiber.StatusNoContent)
}
