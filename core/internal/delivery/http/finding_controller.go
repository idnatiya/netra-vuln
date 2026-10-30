package http

import (
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/usecase"
)

type FindingController struct {
	Log     *logrus.Logger
	UseCase *usecase.FindingUseCase
}

func NewFindingController(useCase *usecase.FindingUseCase, logger *logrus.Logger) *FindingController {
	return &FindingController{Log: logger, UseCase: useCase}
}

// searchRequest reads the filter query parameters shared by /findings and /components.
func searchRequest(ctx fiber.Ctx) (*model.SearchFindingRequest, error) {
	request := &model.SearchFindingRequest{
		Client:          ctx.Query("client"),
		Severity:        ctx.Query("severity"),
		Status:          ctx.Query("status"),
		Query:           ctx.Query("q"),
		ComponentKind:   ctx.Query("component_kind"),
		Component:       ctx.Query("component"),
		IncludeResolved: ctx.Query("include_resolved") == "true",
		Sort:            ctx.Query("sort"),
	}
	hostID, err := intQuery(ctx, "host_id", 0)
	if err != nil {
		return nil, err
	}
	page, err := intQuery(ctx, "page", 1)
	if err != nil {
		return nil, err
	}
	size, err := intQuery(ctx, "size", 0)
	if err != nil {
		return nil, err
	}
	request.HostID, request.Page, request.Size = hostID, int(page), int(size)
	return request, nil
}

func (c *FindingController) List(ctx fiber.Ctx) error {
	request, err := searchRequest(ctx)
	if err != nil {
		return err
	}
	response, paging, err := c.UseCase.Search(ctx.Context(), request)
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.FindingResponse]{Data: response, Paging: paging})
}

func (c *FindingController) Components(ctx fiber.Ctx) error {
	request, err := searchRequest(ctx)
	if err != nil {
		return err
	}
	response, err := c.UseCase.Components(ctx.Context(), request)
	if err != nil {
		return err
	}
	return ctx.JSON(model.WebResponse[[]model.ComponentResponse]{Data: response})
}

func (c *FindingController) Triage(ctx fiber.Ctx) error {
	id, err := idParam(ctx)
	if err != nil {
		return err
	}
	request := new(model.TriageFindingRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	request.ID = id
	if err := c.UseCase.Triage(ctx.Context(), request); err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"id": id, "status": request.Status, "by": middleware.GetAuth(ctx).Username}).Info("Finding triaged")
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *FindingController) TriageComponent(ctx fiber.Ctx) error {
	request := new(model.TriageComponentRequest)
	if err := decode(ctx, request); err != nil {
		return err
	}
	response, err := c.UseCase.TriageComponent(ctx.Context(), request)
	if err != nil {
		return err
	}
	c.Log.WithFields(logrus.Fields{"host_id": request.HostID, "kind": request.Kind, "component": request.Key,
		"status": request.Status, "findings": response.Updated, "by": middleware.GetAuth(ctx).Username}).Info("Component triaged")
	return ctx.JSON(model.WebResponse[*model.TriageComponentResponse]{Data: response})
}
