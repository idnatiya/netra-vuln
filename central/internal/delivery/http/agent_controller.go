package http

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/sirupsen/logrus"

	"netra-vuln/central/internal/delivery/http/middleware"
	"netra-vuln/central/internal/usecase"
)

// AgentController serves the agent API. Requests and responses are pkg/wire
// types as-is (no WebResponse envelope): the agent decodes responses strictly.
type AgentController struct {
	Log           *logrus.Logger
	UseCase       *usecase.AgentUseCase
	EnrollUseCase *usecase.EnrollUseCase
}

func NewAgentController(useCase *usecase.AgentUseCase, enrollUseCase *usecase.EnrollUseCase, logger *logrus.Logger) *AgentController {
	return &AgentController{Log: logger, UseCase: useCase, EnrollUseCase: enrollUseCase}
}

func (c *AgentController) Health(ctx fiber.Ctx) error {
	pingCtx, cancel := context.WithTimeout(ctx.Context(), 2*time.Second)
	defer cancel()
	if err := c.UseCase.Ping(pingCtx); err != nil {
		c.Log.Errorf("healthz: database unreachable : %+v", err)
		return ctx.Status(fiber.StatusServiceUnavailable).SendString("database unreachable")
	}
	return ctx.SendString("ok\n")
}

func (c *AgentController) Enroll(ctx fiber.Ctx) error {
	request := new(wire.EnrollRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	response, err := c.EnrollUseCase.Enroll(ctx.Context(), request)
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"client": request.ClientID, "hostname": request.Hostname, "remote": ctx.IP()}).Info("Host enrolled")
	return ctx.JSON(response)
}

func (c *AgentController) Heartbeat(ctx fiber.Ctx) error {
	request := new(wire.Heartbeat)
	if err := decode(ctx, request); err != nil {
		return err
	}
	if err := c.UseCase.Heartbeat(ctx.Context(), middleware.GetHost(ctx), request); err != nil {
		return err
	}
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *AgentController) Config(ctx fiber.Ctx) error {
	response, err := c.UseCase.ScanConfig(ctx.Context(), middleware.GetHost(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(response)
}

func (c *AgentController) Report(ctx fiber.Ctx) error {
	request := new(wire.Report)
	if err := decode(ctx, request); err != nil {
		return err
	}
	host := middleware.GetHost(ctx)
	report, err := c.UseCase.Report(ctx.Context(), host, request)
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"client": host.Client.Name, "hostname": host.Hostname, "status": report.Status,
		"findings": len(report.Findings)}).Info("Report ingested")
	return ctx.SendStatus(fiber.StatusNoContent)
}
