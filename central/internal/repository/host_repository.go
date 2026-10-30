package repository

import (
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"netra-vuln/central/internal/entity"
)

type HostRepository struct {
	Repository[entity.Host]
	Log *logrus.Logger
}

func NewHostRepository(log *logrus.Logger) *HostRepository {
	return &HostRepository{Log: log}
}

// FindActiveByTokenHash loads an active host with its client.
func (r *HostRepository) FindActiveByTokenHash(db *gorm.DB, host *entity.Host, hash []byte) error {
	return db.Joins("Client").Where("hosts.host_token_hash = ? AND hosts.revoked_at IS NULL", hash).Take(host).Error
}

// FindByIdWithClient loads a host (revoked included) with its client.
func (r *HostRepository) FindByIdWithClient(db *gorm.DB, host *entity.Host, id int64) error {
	return db.Joins("Client").Where("hosts.id = ?", id).Take(host).Error
}

// FindForUpdate locks the host row (SELECT ... FOR UPDATE); use inside a transaction.
func (r *HostRepository) FindForUpdate(db *gorm.DB, host *entity.Host, clientID int64, hostname string) error {
	return db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("client_id = ? AND hostname = ?", clientID, hostname).Take(host).Error
}

// FindAll lists hosts with their client, filtered by client name and hostname when set.
func (r *HostRepository) FindAll(db *gorm.DB, clientName, hostname string) ([]entity.Host, error) {
	q := db.Joins("Client")
	if clientName != "" {
		q = q.Where("Client.name = ?", clientName)
	}
	if hostname != "" {
		q = q.Where("hosts.hostname = ?", hostname)
	}
	var hosts []entity.Host
	err := q.Order("Client.name, hosts.hostname").Find(&hosts).Error
	return hosts, err
}

func (r *HostRepository) Reactivate(db *gorm.DB, hostID int64, meta entity.HostMeta, tokenHash []byte) error {
	cols := meta.Columns()
	cols["host_token_hash"], cols["revoked_at"] = tokenHash, nil
	return db.Model(&entity.Host{}).Where("id = ?", hostID).Updates(cols).Error
}

func (r *HostRepository) Revoke(db *gorm.DB, hostID int64, now time.Time) error {
	return db.Model(&entity.Host{}).Where("id = ? AND revoked_at IS NULL", hostID).Update("revoked_at", now).Error
}

func (r *HostRepository) UpdateHeartbeat(db *gorm.DB, hostID int64, meta entity.HostMeta, now time.Time) error {
	cols := meta.Columns()
	cols["last_heartbeat_at"] = now
	return db.Model(&entity.Host{}).Where("id = ?", hostID).Updates(cols).Error
}

func (r *HostRepository) UpdateScan(db *gorm.DB, hostID int64, rep entity.Report, now time.Time) error {
	cols := rep.Meta.Columns()
	cols["last_scan_at"], cols["last_scan_status"], cols["trivy_version"] = now, string(rep.Status), rep.TrivyVersion
	return db.Model(&entity.Host{}).Where("id = ?", hostID).Updates(cols).Error
}

// Summaries lists hosts (revoked included) with open-finding counts; clientName "" = all.
func (r *HostRepository) Summaries(db *gorm.DB, clientName string) ([]entity.HostSummary, error) {
	var out []entity.HostSummary
	err := db.Raw(`SELECT h.*, c.name AS client_name,
		(SELECT MAX(sc.scanned_at) FROM scans sc WHERE sc.host_id = h.id AND sc.status = 'ok') AS last_ok_scan_at,
		COALESCE(f.crit, 0) AS open_critical, COALESCE(f.high, 0) AS open_high,
		COALESCE(f.acc, 0) AS accepted, COALESCE(f.fp, 0) AS false_positive,
		-- Ingest stamps first_seen and resolved_at with the scan's last_scan_at.
		(SELECT COUNT(*) FROM findings x WHERE x.host_id = h.id AND h.last_scan_status = 'ok'
			AND x.first_seen = h.last_scan_at) AS new_in_last_scan,
		(SELECT COUNT(*) FROM findings x WHERE x.host_id = h.id AND h.last_scan_status = 'ok'
			AND x.resolved_at = h.last_scan_at) AS resolved_in_last_scan,
		(SELECT COUNT(*) FROM scans sc WHERE sc.host_id = h.id AND sc.status = 'ok') <= 1 AS first_scan
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
		ORDER BY c.name, h.hostname`, clientName, clientName).Scan(&out).Error
	return out, err
}

// Distribution counts active hosts by OS, agent version, and Trivy version.
func (r *HostRepository) Distribution(db *gorm.DB) (entity.Distribution, error) {
	var d entity.Distribution
	for _, q := range []struct {
		expr string
		dst  *[]entity.Count
	}{
		{"TRIM(CONCAT(os_name, ' ', os_version))", &d.OS},
		{"agent_version", &d.AgentVersions},
		{"trivy_version", &d.TrivyVersions},
	} {
		// expr is one of the constants above, never user input.
		*q.dst = []entity.Count{}
		if err := db.Raw(`SELECT ` + q.expr + ` AS k, COUNT(*) AS n FROM hosts
			WHERE revoked_at IS NULL GROUP BY k ORDER BY COUNT(*) DESC, k`).Scan(q.dst).Error; err != nil {
			return d, err
		}
	}
	return d, nil
}
