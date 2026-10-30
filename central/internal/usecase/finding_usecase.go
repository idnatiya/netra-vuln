package usecase

import (
	"context"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/central/internal/entity"
	"netra-vuln/central/internal/model"
	"netra-vuln/central/internal/model/converter"
	"netra-vuln/central/internal/repository"
)

type FindingUseCase struct {
	DB                *gorm.DB
	Log               *logrus.Logger
	Validate          *validator.Validate
	FindingRepository *repository.FindingRepository
}

func NewFindingUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate,
	findingRepository *repository.FindingRepository) *FindingUseCase {
	return &FindingUseCase{DB: db, Log: log, Validate: validate, FindingRepository: findingRepository}
}

// normalize applies defaults after validation: page 1, 50 per page (max 200), most severe first.
func normalize(request *model.SearchFindingRequest) {
	request.Page = max(request.Page, 1)
	switch {
	case request.Size <= 0:
		request.Size = model.DefaultPageSize
	case request.Size > model.MaxPageSize:
		request.Size = model.MaxPageSize
	}
	if request.Sort == "" {
		request.Sort = model.SortSeverity
	}
}

func (c *FindingUseCase) Search(ctx context.Context, request *model.SearchFindingRequest) ([]model.FindingResponse, *model.PageMetadata, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, nil, invalid(err)
	}
	normalize(request)
	findings, total, err := c.FindingRepository.Search(c.DB.WithContext(ctx), request)
	if err != nil {
		c.Log.Warnf("Failed search findings : %+v", err)
		return nil, nil, fiber.ErrInternalServerError
	}
	paging := &model.PageMetadata{Page: request.Page, Size: request.Size, TotalItem: total,
		TotalPage: (total + int64(request.Size) - 1) / int64(request.Size)}
	return converter.Map(findings, converter.FindingToResponse), paging, nil
}

func (c *FindingUseCase) Components(ctx context.Context, request *model.SearchFindingRequest) ([]model.ComponentResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	normalize(request)
	rows, err := c.FindingRepository.Components(c.DB.WithContext(ctx), request)
	if err != nil {
		c.Log.Warnf("Failed group components : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(rows, converter.ComponentToResponse), nil
}

func (c *FindingUseCase) Triage(ctx context.Context, request *model.TriageFindingRequest) error {
	if err := c.Validate.Struct(request); err != nil {
		return invalid(err)
	}
	n, err := c.FindingRepository.UpdateTriage(c.DB.WithContext(ctx), request.ID, entity.TriageStatus(request.Status), request.Note)
	if err != nil {
		c.Log.Warnf("Failed triage finding : %+v", err)
		return fiber.ErrInternalServerError
	}
	if n == 0 {
		return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("finding %d not found", request.ID))
	}
	return nil
}

// TriageComponent applies one verdict to every unresolved finding of a component.
func (c *FindingUseCase) TriageComponent(ctx context.Context, request *model.TriageComponentRequest) (*model.TriageComponentResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	n, err := c.FindingRepository.UpdateComponentTriage(c.DB.WithContext(ctx), request.HostID,
		entity.ComponentKind(request.Kind), request.Key, entity.TriageStatus(request.Status), request.Note)
	if err != nil {
		c.Log.Warnf("Failed triage component : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &model.TriageComponentResponse{Updated: int(n)}, nil
}
