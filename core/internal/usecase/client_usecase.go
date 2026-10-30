package usecase

import (
	"context"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
	"netra-vuln/core/internal/model/converter"
	"netra-vuln/core/internal/repository"
)

type ClientUseCase struct {
	DB                    *gorm.DB
	Log                   *logrus.Logger
	Validate              *validator.Validate
	ClientRepository      *repository.ClientRepository
	EnrollTokenRepository *repository.EnrollTokenRepository
	HostRepository        *repository.HostRepository
}

func NewClientUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, clientRepository *repository.ClientRepository,
	enrollTokenRepository *repository.EnrollTokenRepository, hostRepository *repository.HostRepository) *ClientUseCase {
	return &ClientUseCase{DB: db, Log: log, Validate: validate, ClientRepository: clientRepository,
		EnrollTokenRepository: enrollTokenRepository, HostRepository: hostRepository}
}

// Create creates a client and returns its enroll token (shown once).
func (c *ClientUseCase) Create(ctx context.Context, request *model.CreateClientRequest) (*model.CreateClientResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	t := now()
	client := &entity.Client{Name: request.Name, CreatedAt: t}
	if err := c.ClientRepository.Create(tx, client); err != nil {
		if isDuplicate(err) {
			return nil, fiber.NewError(fiber.StatusConflict, fmt.Sprintf("client %q already exists", request.Name))
		}
		c.Log.Warnf("Failed create client : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	token, hash := NewToken()
	if err := c.EnrollTokenRepository.Create(tx, &entity.EnrollToken{ClientID: client.ID, TokenHash: hash, CreatedAt: t}); err != nil {
		c.Log.Warnf("Failed create enroll token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &model.CreateClientResponse{Name: client.Name, EnrollToken: token}, nil
}

// List returns every client with its active hosts and open-finding counts.
func (c *ClientUseCase) List(ctx context.Context) ([]model.ClientResponse, error) {
	ov, err := buildOverview(c.DB.WithContext(ctx), c.ClientRepository, c.HostRepository, "")
	if err != nil {
		c.Log.Warnf("Failed build overview : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(ov.Clients, converter.ClientToResponse), nil
}

// SetScanConfig stores already-validated wire.ScanConfig JSON; nil clears it.
func (c *ClientUseCase) SetScanConfig(ctx context.Context, request *model.SetScanConfigRequest) error {
	if err := c.Validate.Struct(request); err != nil {
		return invalid(err)
	}
	db := c.DB.WithContext(ctx)
	client := new(entity.Client)
	if err := c.ClientRepository.FindByName(db, client, request.Name); err != nil {
		if isNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("client %q not found", request.Name))
		}
		c.Log.Warnf("Failed find client : %+v", err)
		return fiber.ErrInternalServerError
	}
	if err := c.ClientRepository.UpdateScanConfig(db, client.ID, request.Config); err != nil {
		c.Log.Warnf("Failed update scan config : %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}

// buildOverview aggregates active hosts per client; clientName "" = all clients.
func buildOverview(db *gorm.DB, clients *repository.ClientRepository, hosts *repository.HostRepository,
	clientName string) (entity.Overview, error) {
	all, err := clients.FindAll(db)
	if err != nil {
		return entity.Overview{}, err
	}
	if clientName != "" {
		var only []entity.Client
		for _, cl := range all {
			if cl.Name == clientName {
				only = append(only, cl)
			}
		}
		all = only
	}
	summaries, err := hosts.Summaries(db, clientName)
	if err != nil {
		return entity.Overview{}, err
	}
	t := now()
	for i := range summaries {
		summaries[i].MarkStale(t)
	}
	return entity.BuildOverview(all, summaries), nil
}
