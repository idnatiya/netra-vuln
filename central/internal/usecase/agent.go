package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netra-vuln/central/internal/domain"
)

// Agent serves authenticated agent calls: auth, heartbeat, report ingest, config.
type Agent struct {
	Store Store
	Now   func() time.Time
}

func (a *Agent) Authenticate(ctx context.Context, token string) (domain.Host, error) {
	if token == "" {
		return domain.Host{}, domain.ErrUnauthorized
	}
	h, err := a.Store.HostByTokenHash(ctx, HashToken(token))
	if errors.Is(err, domain.ErrNotFound) {
		return h, domain.ErrUnauthorized
	}
	return h, err
}

// checkTenant ensures a host only writes data for itself: the token decides the
// host, and the payload must name the same client and hostname.
func checkTenant(h domain.Host, clientName, hostname string) error {
	if clientName != h.ClientName || hostname != h.Hostname {
		return fmt.Errorf("%w: token belongs to %s/%s, payload names %s/%s",
			domain.ErrForbidden, h.ClientName, h.Hostname, clientName, hostname)
	}
	return nil
}

func (a *Agent) Heartbeat(ctx context.Context, h domain.Host, clientName, hostname string, meta domain.HostMeta) error {
	if err := checkTenant(h, clientName, hostname); err != nil {
		return err
	}
	meta.Normalize()
	return a.Store.UpdateHostHeartbeat(ctx, h.ID, meta, now(a.Now))
}

// Ingest stores a report in one transaction. Failed scans are recorded but never
// touch findings, so a broken scan cannot mark findings as resolved.
func (a *Agent) Ingest(ctx context.Context, h domain.Host, r domain.Report) error {
	if err := checkTenant(h, r.ClientName, r.Hostname); err != nil {
		return err
	}
	t := now(a.Now)
	r.Normalize()
	if err := r.Validate(t); err != nil {
		return err
	}
	return a.Store.InTx(ctx, func(s Store) error {
		if err := s.InsertScan(ctx, h.ID, r, r.Counts()); err != nil {
			return err
		}
		if r.Status == domain.StatusOK {
			if err := s.UpsertFindings(ctx, h.ID, r.Findings, t); err != nil {
				return err
			}
			if err := s.ResolveMissing(ctx, h.ID, t); err != nil {
				return err
			}
		}
		return s.UpdateHostScan(ctx, h.ID, r, t)
	})
}

// ScanConfig returns the client's stored overrides (wire.ScanConfig JSON), or nil.
func (a *Agent) ScanConfig(ctx context.Context, h domain.Host) ([]byte, error) {
	c, err := a.Store.ClientByName(ctx, h.ClientName)
	if err != nil {
		return nil, err
	}
	return c.ScanConfig, nil
}

func (a *Agent) Ping(ctx context.Context) error { return a.Store.Ping(ctx) }
