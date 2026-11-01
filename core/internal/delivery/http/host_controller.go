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
	EOL     *usecase.EOLUseCase
}

func NewHostController(useCase *usecase.HostUseCase, eol *usecase.EOLUseCase, logger *logrus.Logger) *HostController {
	return &HostController{Log: logger, UseCase: useCase, EOL: eol}
}

// Software lists the host's installed products with their end-of-life status.
func (c *HostController) Software(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	response, err := c.EOL.HostSoftware(ctx.Context(), id)
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.SoftwareResponse]{Data: response})
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

func (c *HostController) Delete(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	if err := c.UseCase.Delete(ctx.Context(), id); err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"host_id": id, "by": middleware.GetAuth(ctx).Username}).Info("Host deleted")
	return ctx.SendStatus(fiber.StatusNoContent)
}
