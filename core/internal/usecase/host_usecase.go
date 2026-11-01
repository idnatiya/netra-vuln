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

type HostUseCase struct {
	DB             *gorm.DB
	Log            *logrus.Logger
	Validate       *validator.Validate
	HostRepository *repository.HostRepository
	EOL            *EOLUseCase // annotates hosts with end-of-life software
}

// Delete permanently removes a revoked host and its scan and finding history.
func (c *HostUseCase) Delete(ctx context.Context, id int64) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()
	host := new(entity.Host)
	if err := tx.First(host, id).Error; err != nil {
		if isNotFound(err) {
			return fiber.ErrNotFound
		}
		return fiber.ErrInternalServerError
	}
	if host.Active() {
		return fiber.NewError(fiber.StatusConflict, "revoke the host before deleting it")
	}
	if err := tx.Where("host_id = ?", id).Delete(&entity.Finding{}).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	if err := tx.Where("host_id = ?", id).Delete(&entity.Scan{}).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	if err := tx.Where("host_id = ?", id).Delete(&entity.Software{}).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	if err := tx.Delete(host).Error; err != nil {
		return fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		return fiber.ErrInternalServerError
	}
	return nil
}

func NewHostUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, hostRepository *repository.HostRepository) *HostUseCase {
	return &HostUseCase{DB: db, Log: log, Validate: validate, HostRepository: hostRepository}
}

// Search lists hosts (revoked included) with open-finding counts and stale flags.
func (c *HostUseCase) Search(ctx context.Context, request *model.SearchHostRequest) ([]model.HostResponse, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	hosts, err := c.HostRepository.Summaries(c.DB.WithContext(ctx), request.Client)
	if err != nil {
		c.Log.Warnf("Failed list hosts : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	t := now()
	for i := range hosts {
		hosts[i].MarkStale(t)
	}
	if err := c.EOL.Annotate(c.DB.WithContext(ctx), hosts); err != nil {
		c.Log.Warnf("Failed evaluate end of life : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return converter.Map(hosts, converter.HostToResponse), nil
}

// FindAll lists hosts with their client, for the CLI.
func (c *HostUseCase) FindAll(ctx context.Context, request *model.SearchHostRequest) ([]entity.Host, error) {
	hosts, err := c.HostRepository.FindAll(c.DB.WithContext(ctx), request.Client, "")
	if err != nil {
		c.Log.Warnf("Failed list hosts : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return hosts, nil
}

// Revoke revokes an active host by id; its token stops working at once.
func (c *HostUseCase) Revoke(ctx context.Context, request *model.RevokeHostRequest) (*entity.Host, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	host := new(entity.Host)
	if err := c.HostRepository.FindByIdWithClient(tx, host, request.ID); err != nil {
		if isNotFound(err) {
			return nil, fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("host %d not found", request.ID))
		}
		c.Log.Warnf("Failed find host : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if !host.Active() {
		return nil, fiber.NewError(fiber.StatusConflict, fmt.Sprintf("host %s/%s is already revoked", host.Client.Name, host.Hostname))
	}
	return host, c.revoke(tx, host)
}

// RevokeByName revokes the active host with that hostname (CLI). Client is
// needed only when the hostname exists in more than one client.
func (c *HostUseCase) RevokeByName(ctx context.Context, request *model.RevokeHostByNameRequest) (*entity.Host, error) {
	if err := c.Validate.Struct(request); err != nil {
		return nil, invalid(err)
	}
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	hosts, err := c.HostRepository.FindAll(tx, request.Client, request.Hostname)
	if err != nil {
		c.Log.Warnf("Failed find host : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	var active []entity.Host
	for _, h := range hosts {
		if h.Active() {
			active = append(active, h)
		}
	}
	switch len(active) {
	case 0:
		return nil, fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("active host %q not found", request.Hostname))
	case 1:
		return &active[0], c.revoke(tx, &active[0])
	default:
		return nil, fiber.NewError(fiber.StatusConflict,
			fmt.Sprintf("hostname %q exists in %d clients, pass --client", request.Hostname, len(active)))
	}
}

func (c *HostUseCase) revoke(tx *gorm.DB, host *entity.Host) error {
	if err := c.HostRepository.Revoke(tx, host.ID, now()); err != nil {
		c.Log.Warnf("Failed revoke host : %+v", err)
		return fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}
	c.Log.Infof("Host revoked : %s/%s", host.Client.Name, host.Hostname)
	return nil
}
