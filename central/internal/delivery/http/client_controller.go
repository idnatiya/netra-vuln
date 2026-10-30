package http

import (
	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/sirupsen/logrus"

	"netra-vuln/central/internal/delivery/http/middleware"
	"netra-vuln/central/internal/model"
	"netra-vuln/central/internal/usecase"
)

type ClientController struct {
	Log     *logrus.Logger
	UseCase *usecase.ClientUseCase
}

func NewClientController(useCase *usecase.ClientUseCase, logger *logrus.Logger) *ClientController {
	return &ClientController{Log: logger, UseCase: useCase}
}

func (c *ClientController) List(ctx fiber.Ctx) error {
	response, err := c.UseCase.List(ctx.Context())
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.ClientResponse]{Data: response})
}

func (c *ClientController) Create(ctx fiber.Ctx) error {
	request := new(model.CreateClientRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	response, err := c.UseCase.Create(ctx.Context(), request)
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"client": response.Name, "by": middleware.GetAuth(ctx).Username}).Info("Client created")
	return ctx.Status(fiber.StatusCreated).JSON(model.WebResponse[*model.CreateClientResponse]{Data: response})
}

// SetScanConfig validates the body as wire.ScanConfig (the fields and values
// the agent accepts) and returns the normalized JSON that was stored.
func (c *ClientController) SetScanConfig(ctx fiber.Ctx) error {
	cfg, err := wire.ParseScanConfig(middleware.GetBody(ctx))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if err := c.UseCase.SetScanConfig(ctx.Context(), &model.SetScanConfigRequest{Name: ctx.Params("name"), Config: cfg}); err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[wireJSON]{Data: cfg})
}

func (c *ClientController) ClearScanConfig(ctx fiber.Ctx) error {
	if err := c.UseCase.SetScanConfig(ctx.Context(), &model.SetScanConfigRequest{Name: ctx.Params("name")}); err != nil {
		return err
	}
	return ctx.SendStatus(fiber.StatusNoContent)
}

// wireJSON embeds already-encoded JSON in a response.
type wireJSON []byte

func (w wireJSON) MarshalJSON() ([]byte, error) { return w, nil }
