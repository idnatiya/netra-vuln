package http

import (
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

type DashboardController struct {
	Log     *logrus.Logger
	UseCase *usecase.DashboardUseCase
}

func NewDashboardController(useCase *usecase.DashboardUseCase, logger *logrus.Logger) *DashboardController {
	return &DashboardController{Log: logger, UseCase: useCase}
}

func (c *DashboardController) Overview(ctx fiber.Ctx) error {
	response, err := c.UseCase.Overview(ctx.Context(), &model.OverviewRequest{Client: ctx.Query("client")})
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[*model.OverviewResponse]{Data: response})
}

func (c *DashboardController) Trend(ctx fiber.Ctx) error {
	hostID, err := intQuery(ctx, "host_id", 0)
	if err != nil {
		return err
	}
	days, err := intQuery(ctx, "days", 30)
	if err != nil {
		return err
	}
	response, err := c.UseCase.Trend(ctx.Context(), &model.TrendRequest{Client: ctx.Query("client"), HostID: hostID, Days: int(days)})
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.TrendResponse]{Data: response})
}

func (c *DashboardController) OldestCVEs(ctx fiber.Ctx) error {
	limit, err := intQuery(ctx, "limit", 20)
	if err != nil {
		return err
	}
	response, err := c.UseCase.OldestCVEs(ctx.Context(), &model.OldestCVERequest{Client: ctx.Query("client"), Limit: int(limit)})
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.CVEAgeResponse]{Data: response})
}

func (c *DashboardController) Distribution(ctx fiber.Ctx) error {
	response, err := c.UseCase.Distribution(ctx.Context())
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[*model.DistributionResponse]{Data: response})
}
