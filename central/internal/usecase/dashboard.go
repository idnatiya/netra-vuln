package usecase

import (
	"context"
	"fmt"
	"time"

	"netra-vuln/central/internal/domain"
)

// Dashboard serves the admin UI: read views plus triage, client, and host actions.
type Dashboard struct {
	Queries DashboardQueries
	Store   Store
	Admin   *Admin
	Now     func() time.Time
}

func (d *Dashboard) Hosts(ctx context.Context, clientName string) ([]domain.HostRow, error) {
	hosts, err := d.Queries.HostRows(ctx, clientName)
	if err != nil {
		return nil, err
	}
	t := now(d.Now)
	for i := range hosts {
		hosts[i].MarkStale(t)
	}
	return hosts, nil
}

func (d *Dashboard) Overview(ctx context.Context, clientName string) (domain.Overview, error) {
	clients, err := d.Store.ListClients(ctx)
	if err != nil {
		return domain.Overview{}, err
	}
	if clientName != "" {
		var only []domain.Client
		for _, c := range clients {
			if c.Name == clientName {
				only = append(only, c)
			}
		}
		clients = only
	}
	hosts, err := d.Hosts(ctx, clientName)
	if err != nil {
		return domain.Overview{}, err
	}
	return domain.BuildOverview(clients, hosts), nil
}

func (d *Dashboard) Clients(ctx context.Context) ([]domain.ClientRow, error) {
	ov, err := d.Overview(ctx, "")
	return ov.Clients, err
}

func (d *Dashboard) Findings(ctx context.Context, f domain.FindingFilter) (domain.Page[domain.FindingRow], error) {
	if err := f.Normalize(); err != nil {
		return domain.Page[domain.FindingRow]{}, err
	}
	return d.Queries.Findings(ctx, f)
}

func (d *Dashboard) Components(ctx context.Context, f domain.FindingFilter) ([]domain.ComponentRow, error) {
	if err := f.Normalize(); err != nil {
		return nil, err
	}
	return d.Queries.Components(ctx, f)
}

func (d *Dashboard) Trend(ctx context.Context, clientName string, hostID int64, days int) ([]domain.TrendPoint, error) {
	if days < 1 || days > 365 {
		return nil, fmt.Errorf("%w: days must be 1-365", domain.ErrInvalid)
	}
	since := now(d.Now).AddDate(0, 0, -days)
	return d.Queries.Trend(ctx, clientName, hostID, since)
}

func (d *Dashboard) OldestCVEs(ctx context.Context, clientName string, limit int) ([]domain.CVEAge, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("%w: limit must be 1-100", domain.ErrInvalid)
	}
	return d.Queries.OldestCVEs(ctx, clientName, limit)
}

func (d *Dashboard) Distribution(ctx context.Context) (domain.Distribution, error) {
	return d.Queries.Distribution(ctx)
}

func (d *Dashboard) TriageFinding(ctx context.Context, id int64, status domain.TriageStatus, note string) error {
	if !status.Valid() {
		return fmt.Errorf("%w: status %q", domain.ErrInvalid, status)
	}
	if len(note) > domain.MaxNoteLength {
		return fmt.Errorf("%w: note longer than %d bytes", domain.ErrInvalid, domain.MaxNoteLength)
	}
	return d.Store.UpdateFindingTriage(ctx, id, status, note)
}

func (d *Dashboard) RevokeHost(ctx context.Context, id int64) (domain.Host, error) {
	h, err := d.Store.HostByID(ctx, id)
	if err != nil {
		return h, err
	}
	if !h.Active() {
		return h, fmt.Errorf("%w: host %s/%s is already revoked", domain.ErrConflict, h.ClientName, h.Hostname)
	}
	return h, d.Store.RevokeHost(ctx, id, now(d.Now))
}

func (d *Dashboard) CreateClient(ctx context.Context, name string) (string, error) {
	return d.Admin.CreateClient(ctx, name)
}

// SetScanConfig stores already-validated wire.ScanConfig JSON; nil clears it.
func (d *Dashboard) SetScanConfig(ctx context.Context, clientName string, cfg []byte) error {
	return d.Admin.SetScanConfig(ctx, clientName, cfg)
}
