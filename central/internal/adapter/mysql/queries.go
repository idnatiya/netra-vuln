package mysql

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"netra-vuln/central/internal/domain"
)

// Read side for the admin dashboard (usecase.DashboardQueries).

func (s *Store) HostRows(ctx context.Context, clientName string) ([]domain.HostRow, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+hostColumns+`,
		(SELECT MAX(sc.scanned_at) FROM scans sc WHERE sc.host_id = h.id AND sc.status = 'ok'),
		COALESCE(f.crit, 0), COALESCE(f.high, 0), COALESCE(f.acc, 0), COALESCE(f.fp, 0)
		FROM hosts h
		JOIN clients c ON c.id = h.client_id
		LEFT JOIN (
			SELECT host_id,
				SUM(status = 'open' AND severity = 'CRITICAL') crit,
				SUM(status = 'open' AND severity = 'HIGH') high,
				SUM(status = 'accepted') acc,
				SUM(status = 'false_positive') fp
			FROM findings WHERE resolved_at IS NULL GROUP BY host_id
		) f ON f.host_id = h.id
		WHERE (? = '' OR c.name = ?)
		ORDER BY c.name, h.hostname`, clientName, clientName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.HostRow
	for rows.Next() {
		var r domain.HostRow
		var lastOK sql.NullTime
		h, err := scanHost(rows, &lastOK, &r.OpenCritical, &r.OpenHigh, &r.Accepted, &r.FalsePositive)
		if err != nil {
			return nil, err
		}
		r.Host, r.LastOKScanAt = h, nullTime(lastOK)
		out = append(out, r)
	}
	return out, rows.Err()
}

// likeEscaper escapes LIKE wildcards; MySQL's default escape character is '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *Store) Findings(ctx context.Context, f domain.FindingFilter) (domain.Page[domain.FindingRow], error) {
	var page domain.Page[domain.FindingRow]
	where := []string{"h.revoked_at IS NULL"}
	var args []any
	add := func(cond string, a ...any) { where = append(where, cond); args = append(args, a...) }
	if f.Client != "" {
		add("c.name = ?", f.Client)
	}
	if f.HostID != 0 {
		add("h.id = ?", f.HostID)
	}
	if f.Severity != "" {
		add("f.severity = ?", f.Severity)
	}
	if f.Status != "" {
		add("f.status = ?", string(f.Status))
	}
	if !f.IncludeResolved {
		add("f.resolved_at IS NULL")
	}
	if f.Query != "" {
		q := "%" + likeEscaper.Replace(f.Query) + "%"
		add("(f.cve LIKE ? OR f.pkg LIKE ?)", q, q)
	}
	from := ` FROM findings f JOIN hosts h ON h.id = f.host_id JOIN clients c ON c.id = h.client_id WHERE ` +
		strings.Join(where, " AND ")

	if err := s.q.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&page.Total); err != nil {
		return page, err
	}

	order := map[string]string{
		domain.SortSeverity:  `FIELD(f.severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'), f.first_seen, f.id`,
		domain.SortFirstSeen: `f.first_seen, f.id`,
		domain.SortLastSeen:  `f.last_seen DESC, f.id DESC`,
	}[f.Sort]
	rows, err := s.q.QueryContext(ctx, `SELECT f.id, f.host_id, c.name, h.hostname, f.target, f.type, f.cve,
		f.pkg, f.installed_version, f.fixed_version, f.severity, f.title, f.status, f.note,
		f.first_seen, f.last_seen, f.resolved_at`+from+` ORDER BY `+order+` LIMIT ? OFFSET ?`,
		append(args, f.PageSize, (f.Page-1)*f.PageSize)...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	page.Items = []domain.FindingRow{}
	for rows.Next() {
		var r domain.FindingRow
		var note sql.NullString
		var resolved sql.NullTime
		if err := rows.Scan(&r.ID, &r.HostID, &r.ClientName, &r.Hostname, &r.Target, &r.Type, &r.CVE,
			&r.Pkg, &r.InstalledVersion, &r.FixedVersion, &r.Severity, &r.Title, &r.Status, &note,
			&r.FirstSeen, &r.LastSeen, &resolved); err != nil {
			return page, err
		}
		r.Note, r.ResolvedAt = note.String, nullTime(resolved)
		page.Items = append(page.Items, r)
	}
	return page, rows.Err()
}

// Trend sums, per UTC day, the last successful scan of each active host that day.
// ponytail: a host that skipped a day simply drops out of that day's sum; carry
// its previous value forward if gaps make the chart misleading.
func (s *Store) Trend(ctx context.Context, clientName string, hostID int64, since time.Time) ([]domain.TrendPoint, error) {
	rows, err := s.q.QueryContext(ctx, `WITH daily AS (
			SELECT DATE(sc.scanned_at) AS day, sc.critical, sc.high,
				ROW_NUMBER() OVER (PARTITION BY sc.host_id, DATE(sc.scanned_at) ORDER BY sc.scanned_at DESC) AS rn
			FROM scans sc
			JOIN hosts h ON h.id = sc.host_id
			JOIN clients c ON c.id = h.client_id
			WHERE sc.status = 'ok' AND sc.scanned_at >= ? AND h.revoked_at IS NULL
				AND (? = '' OR c.name = ?) AND (? = 0 OR h.id = ?)
		)
		SELECT day, SUM(critical), SUM(high) FROM daily WHERE rn = 1 GROUP BY day ORDER BY day`,
		since, clientName, clientName, hostID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.TrendPoint{}
	for rows.Next() {
		var p domain.TrendPoint
		if err := rows.Scan(&p.Day, &p.Critical, &p.High); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) OldestCVEs(ctx context.Context, clientName string, limit int) ([]domain.CVEAge, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT f.cve, ANY_VALUE(f.severity), ANY_VALUE(f.title),
			MIN(f.first_seen) AS oldest, COUNT(DISTINCT f.host_id) AS hosts
		FROM findings f
		JOIN hosts h ON h.id = f.host_id
		JOIN clients c ON c.id = h.client_id
		WHERE f.resolved_at IS NULL AND f.status = 'open' AND h.revoked_at IS NULL AND (? = '' OR c.name = ?)
		GROUP BY f.cve
		ORDER BY oldest, FIELD(ANY_VALUE(f.severity), 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'), hosts DESC, f.cve
		LIMIT ?`, clientName, clientName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.CVEAge{}
	for rows.Next() {
		var a domain.CVEAge
		if err := rows.Scan(&a.CVE, &a.Severity, &a.Title, &a.FirstSeen, &a.Hosts); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) Distribution(ctx context.Context) (domain.Distribution, error) {
	var d domain.Distribution
	for _, q := range []struct {
		expr string
		dst  *[]domain.Count
	}{
		{"TRIM(CONCAT(os_name, ' ', os_version))", &d.OS},
		{"agent_version", &d.AgentVersions},
		{"trivy_version", &d.TrivyVersions},
	} {
		// expr is one of the constants above, never user input.
		rows, err := s.q.QueryContext(ctx, `SELECT `+q.expr+` AS k, COUNT(*) FROM hosts
			WHERE revoked_at IS NULL GROUP BY k ORDER BY COUNT(*) DESC, k`)
		if err != nil {
			return d, err
		}
		*q.dst = []domain.Count{}
		for rows.Next() {
			var c domain.Count
			if err := rows.Scan(&c.Key, &c.N); err != nil {
				rows.Close()
				return d, err
			}
			*q.dst = append(*q.dst, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return d, err
		}
	}
	return d, nil
}
