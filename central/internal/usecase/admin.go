package usecase

import (
	"context"
	"fmt"
	"time"

	"netra-vuln/central/internal/domain"
)

// Admin backs the `central` CLI subcommands.
type Admin struct {
	Store Store
	Now   func() time.Time
}

// CreateClient creates a client and returns its enroll token (shown once).
func (a *Admin) CreateClient(ctx context.Context, name string) (string, error) {
	if err := domain.ValidateClientName(name); err != nil {
		return "", err
	}
	token, hash := NewToken()
	t := now(a.Now)
	err := a.Store.InTx(ctx, func(s Store) error {
		id, err := s.CreateClient(ctx, name, t)
		if err != nil {
			return err
		}
		return s.InsertEnrollToken(ctx, id, hash, t)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// SetScanConfig stores cfg (already-validated wire.ScanConfig JSON); nil clears it.
func (a *Admin) SetScanConfig(ctx context.Context, clientName string, cfg []byte) error {
	c, err := a.Store.ClientByName(ctx, clientName)
	if err != nil {
		return fmt.Errorf("client %q: %w", clientName, err)
	}
	return a.Store.SetClientScanConfig(ctx, c.ID, cfg)
}

func (a *Admin) ListClients(ctx context.Context) ([]domain.Client, error) {
	return a.Store.ListClients(ctx)
}

func (a *Admin) ListHosts(ctx context.Context, clientName string) ([]domain.Host, error) {
	return a.Store.ListHosts(ctx, clientName, "")
}

// RevokeHost revokes the active host with that hostname. clientName is needed
// only when the hostname exists in more than one client.
func (a *Admin) RevokeHost(ctx context.Context, hostname, clientName string) (domain.Host, error) {
	hosts, err := a.Store.ListHosts(ctx, clientName, hostname)
	if err != nil {
		return domain.Host{}, err
	}
	var active []domain.Host
	for _, h := range hosts {
		if h.Active() {
			active = append(active, h)
		}
	}
	switch len(active) {
	case 0:
		return domain.Host{}, fmt.Errorf("active host %q: %w", hostname, domain.ErrNotFound)
	case 1:
		return active[0], a.Store.RevokeHost(ctx, active[0].ID, now(a.Now))
	default:
		return domain.Host{}, fmt.Errorf("%w: hostname %q exists in %d clients, pass --client",
			domain.ErrConflict, hostname, len(active))
	}
}
