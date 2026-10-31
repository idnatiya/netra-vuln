package http

import (
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

// McpTokenController manages the signed-in admin's MCP tokens.
type McpTokenController struct {
	Log     *logrus.Logger
	UseCase *usecase.McpTokenUseCase
}

func NewMcpTokenController(useCase *usecase.McpTokenUseCase, logger *logrus.Logger) *McpTokenController {
	return &McpTokenController{Log: logger, UseCase: useCase}
}

func (c *McpTokenController) List(ctx fiber.Ctx) error {
	response, err := c.UseCase.List(ctx.Context(), middleware.GetAuth(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.McpTokenResponse]{Data: response})
}

func (c *McpTokenController) Create(ctx fiber.Ctx) error {
	request := new(model.CreateMcpTokenRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	auth := middleware.GetAuth(ctx)
	response, err := c.UseCase.Create(ctx.Context(), auth, request)
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"by": auth.Username, "name": response.Name}).Info("MCP token created")
	return ctx.Status(fiber.StatusCreated).JSON(model.WebResponse[*model.CreateMcpTokenResponse]{Data: response})
}

func (c *McpTokenController) Revoke(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	auth := middleware.GetAuth(ctx)
	if err := c.UseCase.Revoke(ctx.Context(), auth, &model.RevokeMcpTokenRequest{ID: id}); err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"by": auth.Username, "id": id}).Info("MCP token revoked")
	return ctx.SendStatus(fiber.StatusNoContent)
}
