// Package usecase holds central's application logic. Store is implemented by
// adapter/mysql; tests use a fake.
package usecase

import (
	"context"
	"time"

	"netra-vuln/central/internal/domain"
)

// Store is the persistence port. Lookups return domain.ErrNotFound when nothing
// matches; unique-key violations return domain.ErrConflict.
type Store interface {
	// InTx runs fn with a Store bound to one transaction (commit on nil error).
	InTx(ctx context.Context, fn func(Store) error) error
	Ping(ctx context.Context) error

	ClientByName(ctx context.Context, name string) (domain.Client, error)
	ListClients(ctx context.Context) ([]domain.Client, error)
	CreateClient(ctx context.Context, name string, now time.Time) (int64, error)
	SetClientScanConfig(ctx context.Context, clientID int64, cfg []byte) error
	InsertEnrollToken(ctx context.Context, clientID int64, hash []byte, now time.Time) error
	EnrollTokenValid(ctx context.Context, clientID int64, hash []byte) (bool, error)

	// HostByTokenHash returns only active (not revoked) hosts.
	HostByTokenHash(ctx context.Context, hash []byte) (domain.Host, error)
	// HostForUpdate locks the row (SELECT ... FOR UPDATE); use inside InTx.
	HostForUpdate(ctx context.Context, clientID int64, hostname string) (domain.Host, error)
	// ListHosts filters by client name when clientName != "", and by hostname when hostname != "".
	ListHosts(ctx context.Context, clientName, hostname string) ([]domain.Host, error)
	InsertHost(ctx context.Context, clientID int64, hostname string, meta domain.HostMeta, tokenHash []byte, now time.Time) error
	ReactivateHost(ctx context.Context, hostID int64, meta domain.HostMeta, tokenHash []byte) error
	RevokeHost(ctx context.Context, hostID int64, now time.Time) error
	UpdateHostHeartbeat(ctx context.Context, hostID int64, meta domain.HostMeta, now time.Time) error

	InsertScan(ctx context.Context, hostID int64, r domain.Report, c domain.Counts) error
	UpsertFindings(ctx context.Context, hostID int64, findings []domain.Finding, seen time.Time) error
	// ResolveMissing marks open findings of the host not seen at `seen` as resolved.
	ResolveMissing(ctx context.Context, hostID int64, seen time.Time) error
	UpdateHostScan(ctx context.Context, hostID int64, r domain.Report, now time.Time) error

	HostByID(ctx context.Context, id int64) (domain.Host, error)
	// UpdateFindingTriage returns domain.ErrNotFound when no finding has that id.
	UpdateFindingTriage(ctx context.Context, id int64, status domain.TriageStatus, note string) error
	// UpdateComponentTriage triages every unresolved finding of one component on a host
	// and returns how many it changed.
	UpdateComponentTriage(ctx context.Context, hostID int64, kind domain.ComponentKind, component string,
		status domain.TriageStatus, note string) (int, error)

	CreateAdminUser(ctx context.Context, username, passwordHash string, now time.Time) error
	AdminUserByUsername(ctx context.Context, username string) (domain.AdminUser, error)
	ListAdminUsers(ctx context.Context) ([]domain.AdminUser, error)
	SetAdminPassword(ctx context.Context, username, passwordHash string) error
	InsertSession(ctx context.Context, userID int64, tokenHash []byte, now, expires time.Time) error
	// SessionByTokenHash returns only unexpired sessions of active admins.
	SessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (domain.Session, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error
}

// DashboardQueries is the read side for the admin dashboard. Revoked hosts are
// excluded everywhere except HostRows.
type DashboardQueries interface {
	// HostRows lists hosts (revoked included) with open-finding counts; clientName "" = all.
	HostRows(ctx context.Context, clientName string) ([]domain.HostRow, error)
	Findings(ctx context.Context, f domain.FindingFilter) (domain.Page[domain.FindingRow], error)
	// Components groups the findings matching f (Sort and paging ignored).
	Components(ctx context.Context, f domain.FindingFilter) ([]domain.ComponentRow, error)
	Trend(ctx context.Context, clientName string, hostID int64, since time.Time) ([]domain.TrendPoint, error)
	OldestCVEs(ctx context.Context, clientName string, limit int) ([]domain.CVEAge, error)
	Distribution(ctx context.Context) (domain.Distribution, error)
}

// now returns UTC truncated to microseconds, matching DATETIME(6), so values
// written and compared within one ingest are exactly equal.
func now(clock func() time.Time) time.Time {
	return clock().UTC().Truncate(time.Microsecond)
}
