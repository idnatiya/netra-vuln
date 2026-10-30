package usecase

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/central/internal/model"
	"netra-vuln/central/internal/model/converter"
	"netra-vuln/central/internal/repository"
)

// DashboardUseCase serves the read-only views: overview, trend, oldest CVEs, distribution.
type DashboardUseCase struct {
	DB                *gorm.DB
	Log               *logrus.Logger
	Validate          *validator.Validate
	ClientRepository  *repository.ClientRepository
	HostRepository    *repository.HostRepository
	ScanRepository    *repository.ScanRepository
	FindingRepository *repository.FindingRepository
}

func NewDashboardUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, clientRepository *repository.ClientRepository,
	hostRepository *repository.HostRepository, scanRepository *repository.ScanRepository,
	findingRepository *repository.FindingRepository) *DashboardUseCase {
	return &DashboardUseCase{DB: db, Log: log, Validate: validate, ClientRepository: clientRepository,
		HostRepository: hostRepository, ScanRepository: scanRepository, FindingRepository: findingRepository}
}

func (c *DashboardUseCase) Overview(ctx context.Context, request *model.OverviewRequest) (*model.OverviewResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	ov, err := buildOverview(c.DB.WithContext(ctx), c.ClientRepository, c.HostRepository, request.Client)
	if err != nil {
		c.Log.Warnf("Failed build overview : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.OverviewToResponse(ov), nil
}

func (c *DashboardUseCase) Trend(ctx context.Context, request *model.TrendRequest) ([]model.TrendResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	since := now().AddDate(0, 0, -request.Days)
	points, err := c.ScanRepository.Trend(c.DB.WithContext(ctx), request.Client, request.HostID, since)
	if err != nil {
		c.Log.Warnf("Failed load trend : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(points, converter.TrendToResponse), nil
}

func (c *DashboardUseCase) OldestCVEs(ctx context.Context, request *model.OldestCVERequest) ([]model.CVEAgeResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	cves, err := c.FindingRepository.OldestCVEs(c.DB.WithContext(ctx), request.Client, request.Limit)
	if err != nil {
		c.Log.Warnf("Failed load oldest CVEs : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(cves, converter.CVEAgeToResponse), nil
}

func (c *DashboardUseCase) Distribution(ctx context.Context) (*model.DistributionResponse, error) {
	d, err := c.HostRepository.Distribution(c.DB.WithContext(ctx))
	if err != nil {
		c.Log.Warnf("Failed load distribution : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.DistributionToResponse(d), nil
}
