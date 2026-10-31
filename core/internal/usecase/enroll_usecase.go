package usecase

import (
	"context"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model/converter"
	"netra-vuln/core/internal/repository"
)

type EnrollUseCase struct {
	DB                    *gorm.DB
	Log                   *logrus.Logger
	Validate              *validator.Validate
	ClientRepository      *repository.ClientRepository
	EnrollTokenRepository *repository.EnrollTokenRepository
	HostRepository        *repository.HostRepository
}

func NewEnrollUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, clientRepository *repository.ClientRepository,
	enrollTokenRepository *repository.EnrollTokenRepository, hostRepository *repository.HostRepository) *EnrollUseCase {
	return &EnrollUseCase{DB: db, Log: log, Validate: validate, ClientRepository: clientRepository,
		EnrollTokenRepository: enrollTokenRepository, HostRepository: hostRepository}
}

// Enroll registers a host under a client and returns its new host token.
// An active host with the same hostname is a conflict; a revoked one is
// reactivated with a new token and keeps its history.
func (c *EnrollUseCase) Enroll(ctx context.Context, request *wire.EnrollRequest) (*wire.EnrollResponse, error) {
	hostname := entity.NormalizeHostname(request.Hostname)
	if hostname == "" {
		return nil, fiber.NewError(fiber.StatusBadRequest, "hostname is empty")
	}
	meta := converter.WireToMeta(request.Host)
	meta.Normalize()

	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	// Unknown client and bad token look the same to the caller.
	client := new(entity.Client)
	if err := c.ClientRepository.FindByNameForUpdate(tx, client, request.ClientID); err != nil {
		if isNotFound(err) {
			return nil, fiber.ErrUnauthorized
		}
		c.Log.Warnf("Failed find client : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	valid, err := c.EnrollTokenRepository.Consume(tx, client.ID, HashToken(request.EnrollToken), now())
	if err != nil {
		c.Log.Warnf("Failed check enroll token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if !valid {
		return nil, fiber.ErrUnauthorized
	}

	token, hash := NewToken()
	host := new(entity.Host)
	err = c.HostRepository.FindForUpdate(tx, host, client.ID, hostname)
	switch {
	case isNotFound(err):
		host = &entity.Host{ClientID: client.ID, Hostname: hostname, HostTokenHash: hash, Meta: meta, CreatedAt: now()}
		err = tx.Omit("Client").Create(host).Error
	case err != nil:
	case host.Active():
		return nil, fiber.NewError(fiber.StatusConflict,
			fmt.Sprintf("host %q is already enrolled in client %q (revoke it first)", hostname, client.Name))
	default:
		err = c.HostRepository.Reactivate(tx, host.ID, meta, hash)
	}
	if isDuplicate(err) { // a concurrent enroll of the same hostname won
		return nil, fiber.NewError(fiber.StatusConflict, fmt.Sprintf("host %q is already enrolled", hostname))
	}
	if err != nil {
		c.Log.Warnf("Failed enroll host : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &wire.EnrollResponse{HostToken: token}, nil
}
