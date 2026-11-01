package usecase

import (
	"bytes"
	"context"
	"encoding/json"
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

// AgentUseCase serves authenticated agent calls: auth, heartbeat, report ingest, config.
type AgentUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	Validate           *validator.Validate
	HostRepository     *repository.HostRepository
	ScanRepository     *repository.ScanRepository
	FindingRepository  *repository.FindingRepository
	SoftwareRepository *repository.SoftwareRepository
}

func NewAgentUseCase(db *gorm.DB, log *logrus.Logger, validate *validator.Validate, hostRepository *repository.HostRepository,
	scanRepository *repository.ScanRepository, findingRepository *repository.FindingRepository,
	softwareRepository *repository.SoftwareRepository) *AgentUseCase {
	return &AgentUseCase{DB: db, Log: log, Validate: validate, HostRepository: hostRepository,
		ScanRepository: scanRepository, FindingRepository: findingRepository, SoftwareRepository: softwareRepository}
}

// Verify returns the active host that owns token.
func (c *AgentUseCase) Verify(ctx context.Context, token string) (*entity.Host, error) {
	if token == "" {
		return nil, fiber.ErrUnauthorized
	}
	host := new(entity.Host)
	if err := c.HostRepository.FindActiveByTokenHash(c.DB.WithContext(ctx), host, HashToken(token)); err != nil {
		if isNotFound(err) {
			return nil, fiber.ErrUnauthorized
		}
		c.Log.Warnf("Failed find host by token : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return host, nil
}

// checkTenant ensures a host only writes data for itself: the token decides the
// host, and the payload must name the same client and hostname.
func checkTenant(h *entity.Host, clientName, hostname string) error {
	if clientName != h.Client.Name || hostname != h.Hostname {
		return fiber.NewError(fiber.StatusForbidden, fmt.Sprintf("token belongs to %s/%s, payload names %s/%s",
			h.Client.Name, h.Hostname, clientName, hostname))
	}
	return nil
}

func (c *AgentUseCase) Heartbeat(ctx context.Context, host *entity.Host, request *wire.Heartbeat) error {
	if err := checkTenant(host, request.ClientID, request.Hostname); err != nil {
		return err
	}
	meta := converter.WireToMeta(request.Host)
	meta.Normalize()
	if err := c.HostRepository.UpdateHeartbeat(c.DB.WithContext(ctx), host.ID, meta, now()); err != nil {
		c.Log.Warnf("Failed update heartbeat : %+v", err)
		return fiber.ErrInternalServerError
	}
	return nil
}

// Report stores a report in one transaction. Failed scans are recorded but never
// touch findings, so a broken scan cannot mark findings as resolved.
func (c *AgentUseCase) Report(ctx context.Context, host *entity.Host, request *wire.Report) (*entity.Report, error) {
	report := converter.WireToReport(request)
	if err := checkTenant(host, report.ClientName, report.Hostname); err != nil {
		return nil, err
	}
	t := now()
	report.Normalize()
	if err := report.Validate(t); err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "invalid report: "+err.Error())
	}

	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	counts := report.Counts()
	scan := &entity.Scan{HostID: host.ID, ScannedAt: report.ScannedAt.UTC(), Status: report.Status,
		DurationSeconds: report.Duration.Seconds(), Total: counts.Total, Critical: counts.Critical, High: counts.High,
		TrivyVersion: report.TrivyVersion}
	if report.Error != "" {
		scan.ErrorMessage = &report.Error
	}
	if err := c.ScanRepository.Create(tx, scan); err != nil {
		c.Log.Warnf("Failed create scan : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if report.Status == entity.StatusOK {
		findings := make([]entity.Finding, len(report.Findings))
		for i, v := range report.Findings {
			findings[i] = entity.NewFinding(host.ID, v, t)
		}
		if err := c.FindingRepository.Upsert(tx, findings); err != nil {
			c.Log.Warnf("Failed upsert findings : %+v", err)
			return nil, fiber.ErrInternalServerError
		}
		if err := c.FindingRepository.ResolveMissing(tx, host.ID, t); err != nil {
			c.Log.Warnf("Failed resolve missing findings : %+v", err)
			return nil, fiber.ErrInternalServerError
		}
		// Agents before v0.3.0 send no software; keep what an older report stored.
		if len(report.Software) > 0 {
			if err := c.SoftwareRepository.Replace(tx, host.ID, report.Software); err != nil {
				c.Log.Warnf("Failed replace software : %+v", err)
				return nil, fiber.ErrInternalServerError
			}
		}
	}
	if err := c.HostRepository.UpdateScan(tx, host.ID, report, t); err != nil {
		c.Log.Warnf("Failed update host scan : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	return &report, nil
}

// ScanConfig returns the client's overrides, re-decoded strictly into
// wire.ScanConfig so only fields the agent accepts are ever sent.
func (c *AgentUseCase) ScanConfig(ctx context.Context, host *entity.Host) (*wire.ScanConfig, error) {
	cfg := new(wire.ScanConfig)
	raw := host.Client.ScanConfig
	if len(raw) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		c.Log.Errorf("Stored scan_config of client %s is invalid : %+v", host.Client.Name, err)
		return nil, fiber.ErrInternalServerError
	}
	return cfg, nil
}

// Ping checks the database for /healthz.
func (c *AgentUseCase) Ping(ctx context.Context) error {
	sqlDB, err := c.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
