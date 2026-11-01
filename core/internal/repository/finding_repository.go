package repository

import (
	"math"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
)

// upsertBatch keeps one INSERT well below SQLite's 32766 bound-parameter limit.
const upsertBatch = 500

// maxComponentPackages caps the package names listed per component row.
const maxComponentPackages = 20

type FindingRepository struct {
	Repository[entity.Finding]
	Log *logrus.Logger
}

func NewFindingRepository(log *logrus.Logger) *FindingRepository {
	return &FindingRepository{Log: log}
}

// Upsert inserts new findings and refreshes existing ones. first_seen, status
// and note are kept on conflict; a resolved finding reopens. The component is
// refreshed so grouping rule changes apply on the next scan.
func (r *FindingRepository) Upsert(db *gorm.DB, findings []entity.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	return db.Clauses(clause.OnConflict{
		DoUpdates: append(clause.AssignmentColumns([]string{"last_seen", "type", "fixed_version", "severity", "title",
			"pkg_path", "component_kind", "component"}),
			clause.Assignment{Column: clause.Column{Name: "resolved_at"}, Value: nil}),
	}).CreateInBatches(findings, upsertBatch).Error
}

// ResolveMissing marks open findings of the host not seen at `seen` as resolved.
func (r *FindingRepository) ResolveMissing(db *gorm.DB, hostID int64, seen time.Time) error {
	return db.Model(&entity.Finding{}).Where("host_id = ? AND resolved_at IS NULL AND last_seen < ?", hostID, seen).
		Update("resolved_at", seen).Error
}

// noteValue stores an empty note as NULL.
func noteValue(note string) any {
	if note == "" {
		return nil
	}
	return note
}

// UpdateTriage sets one finding's verdict and returns the number of matched rows.
func (r *FindingRepository) UpdateTriage(db *gorm.DB, id int64, status entity.TriageStatus, note string) (int64, error) {
	res := db.Model(&entity.Finding{}).Where("id = ?", id).
		Updates(map[string]any{"status": string(status), "note": noteValue(note)})
	return res.RowsAffected, res.Error // matched rows (clientFoundRows DSN option)
}

// UpdateComponentTriage sets the verdict of every unresolved finding of one
// component on a host and returns how many matched.
func (r *FindingRepository) UpdateComponentTriage(db *gorm.DB, hostID int64, kind entity.ComponentKind,
	component string, status entity.TriageStatus, note string) (int64, error) {
	res := db.Model(&entity.Finding{}).
		Where("host_id = ? AND component_kind = ? AND component = ? AND resolved_at IS NULL", hostID, string(kind), component).
		Updates(map[string]any{"status": string(status), "note": noteValue(note)})
	return res.RowsAffected, res.Error
}

// likeEscaper escapes LIKE wildcards; queries declare ESCAPE '\'.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// filter applies the joins and conditions shared by Search and Components.
func (r *FindingRepository) filter(db *gorm.DB, req *model.SearchFindingRequest) *gorm.DB {
	q := db.Table("findings f").
		Joins("JOIN hosts h ON h.id = f.host_id").
		Joins("JOIN clients c ON c.id = h.client_id").
		Where("h.revoked_at IS NULL")
	if req.Client != "" {
		q = q.Where("c.name = ?", req.Client)
	}
	if req.HostID != 0 {
		q = q.Where("h.id = ?", req.HostID)
	}
	if req.Severity != "" {
		q = q.Where("f.severity = ?", req.Severity)
	}
	if req.Status != "" {
		q = q.Where("f.status = ?", req.Status)
	}
	if !req.IncludeResolved {
		q = q.Where("f.resolved_at IS NULL")
	}
	if req.Query != "" {
		like := "%" + likeEscaper.Replace(req.Query) + "%"
		q = q.Where(`(f.cve LIKE ? ESCAPE '\' OR f.pkg LIKE ? ESCAPE '\')`, like, like)
	}
	if req.ComponentKind != "" {
		q = q.Where("f.component_kind = ? AND f.component = ?", req.ComponentKind, req.Component)
	}
	return q
}

// Search returns one page of matching findings (Page/Size already normalized) and the total.
func (r *FindingRepository) Search(db *gorm.DB, req *model.SearchFindingRequest) ([]entity.FindingSummary, int64, error) {
	var total int64
	if err := r.filter(db, req).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	order := map[string]string{
		model.SortSeverity:  severityRank("f.severity") + `, f.first_seen, f.id`,
		model.SortFirstSeen: `f.first_seen, f.id`,
		model.SortLastSeen:  `f.last_seen DESC, f.id DESC`,
	}[req.Sort]
	findings := []entity.FindingSummary{}
	err := r.filter(db, req).Select("f.*, c.name AS client_name, h.hostname AS hostname").
		Order(order).Limit(req.Size).Offset((req.Page - 1) * req.Size).Scan(&findings).Error
	return findings, total, err
}

// Components groups matching findings per host and component, worst first.
// ponytail: capped at 1000 rows without paging; add paging if a fleet ever exceeds it.
func (r *FindingRepository) Components(db *gorm.DB, req *model.SearchFindingRequest) ([]entity.ComponentSummary, error) {
	out := []entity.ComponentSummary{}
	// DISTINCT in a subquery so GROUP_CONCAT sees each package once, sorted.
	err := db.Table("(?) AS d", r.filter(db, req).Select(`f.host_id, c.name AS client_name, h.hostname,
		f.component_kind, f.component, f.pkg, f.type, f.cve, f.severity, f.first_seen`).Order("f.pkg")).
		Select(`host_id, client_name, hostname, component_kind, component,
		GROUP_CONCAT(DISTINCT pkg) AS packages, GROUP_CONCAT(DISTINCT type) AS types,
		COUNT(DISTINCT pkg) AS pkg_count, COUNT(*) AS findings, COUNT(DISTINCT cve) AS cves,
		SUM(severity = 'CRITICAL') AS critical, SUM(severity = 'HIGH') AS high, MIN(first_seen) AS first_seen`).
		Group("host_id, client_name, hostname, component_kind, component").
		Order("critical DESC, high DESC, findings DESC, component").Limit(1000).Scan(&out).Error
	for i := range out {
		out[i].PackageList = capList(out[i].PackageList, maxComponentPackages)
		out[i].TypeList = sortedList(out[i].TypeList)
	}
	return out, err
}

// OldestCVEs lists open CVEs across active hosts, oldest first.
func (r *FindingRepository) OldestCVEs(db *gorm.DB, clientName string, limit int) ([]entity.CVEAge, error) {
	out := []entity.CVEAge{}
	err := db.Raw(`SELECT f.cve AS cve, MIN(f.severity) AS severity, MIN(f.title) AS title,
			MIN(f.first_seen) AS first_seen, COUNT(DISTINCT f.host_id) AS hosts
		FROM findings f
		JOIN hosts h ON h.id = f.host_id
		JOIN clients c ON c.id = h.client_id
		WHERE f.resolved_at IS NULL AND f.status = 'open' AND h.revoked_at IS NULL AND (? = '' OR c.name = ?)
		GROUP BY f.cve
		ORDER BY first_seen, `+severityRank("MIN(f.severity)")+`, hosts DESC, f.cve
		LIMIT ?`, clientName, clientName, limit).Scan(&out).Error
	return out, err
}

// severityRank orders severities worst first (CRITICAL = 0) in SQL.
func severityRank(col string) string {
	return "CASE " + col + " WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
}

// capList sorts a GROUP_CONCAT (comma-separated) list and keeps the first n.
func capList(list string, n int) string {
	items := strings.Split(list, ",")
	slices.Sort(items)
	return strings.Join(items[:min(n, len(items))], "\n")
}

func sortedList(list string) string { return capList(list, math.MaxInt) }
