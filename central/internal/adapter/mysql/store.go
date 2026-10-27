// Package mysql implements usecase.Store on MySQL 8.
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	driver "github.com/go-sql-driver/mysql"

	"netra-vuln/central/internal/domain"
	"netra-vuln/central/internal/usecase"
)

// upsertBatch keeps one INSERT well below MySQL's 65535 placeholder limit.
const upsertBatch = 500

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db *sql.DB
	q  querier // db, or the *sql.Tx inside InTx
}

func New(db *sql.DB) *Store { return &Store{db: db, q: db} }

// Open parses dsn and forces UTC + parseTime so DATETIME(6) round-trips exactly.
func Open(dsn string, multiStatements bool) (*sql.DB, error) {
	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = multiStatements
	cfg.ClientFoundRows = true // UPDATE reports matched rows, so "no change" != "not found"
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

func (s *Store) InTx(ctx context.Context, fn func(usecase.Store) error) error {
	if _, inTx := s.q.(*sql.Tx); inTx {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit
	if err := fn(&Store{db: s.db, q: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// mapErr turns driver errors into domain errors.
func mapErr(err error) error {
	var me *driver.MySQLError
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return domain.ErrNotFound
	case errors.As(err, &me) && me.Number == 1062: // ER_DUP_ENTRY
		return fmt.Errorf("%w: %s", domain.ErrConflict, me.Message)
	}
	return err
}

func nullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// --- clients & enroll tokens ---

func (s *Store) ClientByName(ctx context.Context, name string) (domain.Client, error) {
	var c domain.Client
	err := s.q.QueryRowContext(ctx,
		`SELECT id, name, scan_config, created_at FROM clients WHERE name = ?`, name,
	).Scan(&c.ID, &c.Name, &c.ScanConfig, &c.CreatedAt)
	return c, mapErr(err)
}

func (s *Store) ListClients(ctx context.Context) ([]domain.Client, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, name, scan_config, created_at FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Client
	for rows.Next() {
		var c domain.Client
		if err := rows.Scan(&c.ID, &c.Name, &c.ScanConfig, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CreateClient(ctx context.Context, name string, now time.Time) (int64, error) {
	res, err := s.q.ExecContext(ctx, `INSERT INTO clients (name, created_at) VALUES (?, ?)`, name, now)
	if err != nil {
		return 0, mapErr(err)
	}
	return res.LastInsertId()
}

func (s *Store) SetClientScanConfig(ctx context.Context, clientID int64, cfg []byte) error {
	var v any // NULL when cfg is nil
	if cfg != nil {
		v = string(cfg)
	}
	_, err := s.q.ExecContext(ctx, `UPDATE clients SET scan_config = ? WHERE id = ?`, v, clientID)
	return err
}

func (s *Store) InsertEnrollToken(ctx context.Context, clientID int64, hash []byte, now time.Time) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO enroll_tokens (client_id, token_hash, created_at) VALUES (?, ?, ?)`, clientID, hash, now)
	return mapErr(err)
}

func (s *Store) EnrollTokenValid(ctx context.Context, clientID int64, hash []byte) (bool, error) {
	var n int
	err := s.q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM enroll_tokens WHERE client_id = ? AND token_hash = ? AND revoked_at IS NULL`,
		clientID, hash).Scan(&n)
	return n > 0, err
}

// --- hosts ---

const hostColumns = `h.id, h.client_id, c.name, h.hostname, h.os_family, h.os_name, h.os_version,
	h.arch, h.kernel_running, h.agent_version, h.trivy_version, h.reboot_required,
	h.auto_update_enabled, h.last_heartbeat_at, h.last_scan_at, h.last_scan_status,
	h.created_at, h.revoked_at`

// scanHost scans hostColumns, followed by any extra destinations.
func scanHost(row interface{ Scan(...any) error }, extra ...any) (domain.Host, error) {
	var (
		h                        domain.Host
		heartbeat, scan, revoked sql.NullTime
		status                   sql.NullString
	)
	dest := append([]any{&h.ID, &h.ClientID, &h.ClientName, &h.Hostname, &h.Meta.OSFamily, &h.Meta.OSName,
		&h.Meta.OSVersion, &h.Meta.Arch, &h.Meta.KernelRunning, &h.Meta.AgentVersion, &h.TrivyVersion,
		&h.Meta.RebootRequired, &h.Meta.AutoUpdateEnabled, &heartbeat, &scan, &status,
		&h.CreatedAt, &revoked}, extra...)
	err := row.Scan(dest...)
	h.LastHeartbeatAt, h.LastScanAt, h.RevokedAt = nullTime(heartbeat), nullTime(scan), nullTime(revoked)
	h.LastScanStatus = domain.ScanStatus(status.String)
	return h, mapErr(err)
}

func (s *Store) HostByTokenHash(ctx context.Context, hash []byte) (domain.Host, error) {
	return scanHost(s.q.QueryRowContext(ctx, `SELECT `+hostColumns+`
		FROM hosts h JOIN clients c ON c.id = h.client_id
		WHERE h.host_token_hash = ? AND h.revoked_at IS NULL`, hash))
}

func (s *Store) HostForUpdate(ctx context.Context, clientID int64, hostname string) (domain.Host, error) {
	return scanHost(s.q.QueryRowContext(ctx, `SELECT `+hostColumns+`
		FROM hosts h JOIN clients c ON c.id = h.client_id
		WHERE h.client_id = ? AND h.hostname = ? FOR UPDATE`, clientID, hostname))
}

func (s *Store) ListHosts(ctx context.Context, clientName, hostname string) ([]domain.Host, error) {
	q := `SELECT ` + hostColumns + ` FROM hosts h JOIN clients c ON c.id = h.client_id WHERE 1=1`
	var args []any
	if clientName != "" {
		q += ` AND c.name = ?`
		args = append(args, clientName)
	}
	if hostname != "" {
		q += ` AND h.hostname = ?`
		args = append(args, hostname)
	}
	rows, err := s.q.QueryContext(ctx, q+` ORDER BY c.name, h.hostname`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) InsertHost(ctx context.Context, clientID int64, hostname string, m domain.HostMeta, tokenHash []byte, now time.Time) error {
	_, err := s.q.ExecContext(ctx, `INSERT INTO hosts
		(client_id, hostname, host_token_hash, os_family, os_name, os_version, arch, kernel_running,
		 agent_version, reboot_required, auto_update_enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clientID, hostname, tokenHash, m.OSFamily, m.OSName, m.OSVersion, m.Arch, m.KernelRunning,
		m.AgentVersion, m.RebootRequired, m.AutoUpdateEnabled, now)
	return mapErr(err)
}

func (s *Store) ReactivateHost(ctx context.Context, hostID int64, m domain.HostMeta, tokenHash []byte) error {
	_, err := s.q.ExecContext(ctx, `UPDATE hosts SET host_token_hash = ?, revoked_at = NULL,
		os_family = ?, os_name = ?, os_version = ?, arch = ?, kernel_running = ?, agent_version = ?,
		reboot_required = ?, auto_update_enabled = ? WHERE id = ?`,
		tokenHash, m.OSFamily, m.OSName, m.OSVersion, m.Arch, m.KernelRunning, m.AgentVersion,
		m.RebootRequired, m.AutoUpdateEnabled, hostID)
	return mapErr(err)
}

func (s *Store) RevokeHost(ctx context.Context, hostID int64, now time.Time) error {
	_, err := s.q.ExecContext(ctx, `UPDATE hosts SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, hostID)
	return err
}

func (s *Store) UpdateHostHeartbeat(ctx context.Context, hostID int64, m domain.HostMeta, now time.Time) error {
	_, err := s.q.ExecContext(ctx, `UPDATE hosts SET last_heartbeat_at = ?,
		os_family = ?, os_name = ?, os_version = ?, arch = ?, kernel_running = ?, agent_version = ?,
		reboot_required = ?, auto_update_enabled = ? WHERE id = ?`,
		now, m.OSFamily, m.OSName, m.OSVersion, m.Arch, m.KernelRunning, m.AgentVersion,
		m.RebootRequired, m.AutoUpdateEnabled, hostID)
	return err
}

// --- ingest ---

func (s *Store) InsertScan(ctx context.Context, hostID int64, r domain.Report, c domain.Counts) error {
	var errMsg any
	if r.Error != "" {
		errMsg = r.Error
	}
	_, err := s.q.ExecContext(ctx, `INSERT INTO scans
		(host_id, scanned_at, status, error_message, duration_seconds, total, critical, high, trivy_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hostID, r.ScannedAt.UTC(), string(r.Status), errMsg, r.Duration.Seconds(),
		c.Total, c.Critical, c.High, r.TrivyVersion)
	return err
}

func (s *Store) UpsertFindings(ctx context.Context, hostID int64, findings []domain.Finding, seen time.Time) error {
	for start := 0; start < len(findings); start += upsertBatch {
		batch := findings[start:min(start+upsertBatch, len(findings))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO findings (host_id, finding_key, target, type, cve, pkg, pkg_path,
			component_kind, component, installed_version, fixed_version, severity, title, first_seen, last_seen) VALUES `)
		args := make([]any, 0, len(batch)*15)
		for i, f := range batch {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
			kind, component := f.Component()
			args = append(args, hostID, f.Key(), f.Target, f.Type, f.CVE, f.Pkg, f.PkgPath,
				string(kind), component, f.InstalledVersion, f.FixedVersion, f.Severity, f.Title, seen, seen)
		}
		// first_seen, status and note are kept on conflict; a resolved finding reopens.
		// The component is refreshed so grouping rule changes apply on the next scan.
		sb.WriteString(` AS new ON DUPLICATE KEY UPDATE last_seen = new.last_seen, resolved_at = NULL,
			type = new.type, fixed_version = new.fixed_version, severity = new.severity, title = new.title,
			pkg_path = new.pkg_path, component_kind = new.component_kind, component = new.component`)
		if _, err := s.q.ExecContext(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("upsert findings: %w", err)
		}
	}
	return nil
}

func (s *Store) ResolveMissing(ctx context.Context, hostID int64, seen time.Time) error {
	_, err := s.q.ExecContext(ctx, `UPDATE findings SET resolved_at = ?
		WHERE host_id = ? AND resolved_at IS NULL AND last_seen < ?`, seen, hostID, seen)
	return err
}

func (s *Store) UpdateHostScan(ctx context.Context, hostID int64, r domain.Report, now time.Time) error {
	m := r.Meta
	_, err := s.q.ExecContext(ctx, `UPDATE hosts SET last_scan_at = ?, last_scan_status = ?, trivy_version = ?,
		os_family = ?, os_name = ?, os_version = ?, arch = ?, kernel_running = ?, agent_version = ?,
		reboot_required = ?, auto_update_enabled = ? WHERE id = ?`,
		now, string(r.Status), r.TrivyVersion, m.OSFamily, m.OSName, m.OSVersion, m.Arch,
		m.KernelRunning, m.AgentVersion, m.RebootRequired, m.AutoUpdateEnabled, hostID)
	return err
}
