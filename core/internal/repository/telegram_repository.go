package repository

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"netra-vuln/core/internal/entity"
)

type TelegramRepository struct {
	Log *logrus.Logger
}

func NewTelegramRepository(log *logrus.Logger) *TelegramRepository {
	return &TelegramRepository{Log: log}
}

func (r *TelegramRepository) Chats(db *gorm.DB) ([]entity.TelegramChat, error) {
	var out []entity.TelegramChat
	err := db.Preload("Client").Order("chat_id").Find(&out).Error
	return out, err
}

func (r *TelegramRepository) FindChat(db *gorm.DB, chatID int64) (*entity.TelegramChat, error) {
	chat := new(entity.TelegramChat)
	err := db.Where("chat_id = ?", chatID).Take(chat).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return chat, err
}

// State reads a notifier value; "" when unset.
func (r *TelegramRepository) State(db *gorm.DB, key string) (string, error) {
	var v []string
	err := db.Raw("SELECT value FROM notify_state WHERE key = ?", key).Scan(&v).Error
	if err != nil || len(v) == 0 {
		return "", err
	}
	return v[0], nil
}

func (r *TelegramRepository) SetState(db *gorm.DB, key, value string) error {
	return db.Exec("INSERT INTO notify_state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value).Error
}

func (r *TelegramRepository) Alerts(db *gorm.DB) ([]entity.NotifyAlert, error) {
	var out []entity.NotifyAlert
	return out, db.Find(&out).Error
}

func (r *TelegramRepository) AddAlert(db *gorm.DB, a entity.NotifyAlert) error {
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&a).Error
}

func (r *TelegramRepository) DeleteAlert(db *gorm.DB, a entity.NotifyAlert) error {
	return db.Where("host_id = ? AND kind = ? AND label = ?", a.HostID, a.Kind, a.Label).Delete(&entity.NotifyAlert{}).Error
}

// ScannedHosts lists hosts with a scan after lastID, and the newest scan id.
func (r *TelegramRepository) ScannedHosts(db *gorm.DB, lastID int64) ([]int64, int64, error) {
	var rows []struct {
		HostID int64
		MaxID  int64
	}
	err := db.Raw("SELECT host_id, MAX(id) AS max_id FROM scans WHERE id > ? GROUP BY host_id", lastID).Scan(&rows).Error
	maxID := lastID
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.HostID)
		maxID = max(maxID, row.MaxID)
	}
	return ids, maxID, err
}

func (r *TelegramRepository) MaxScanID(db *gorm.DB) (int64, error) {
	var id int64
	return id, db.Raw("SELECT COALESCE(MAX(id), 0) FROM scans").Scan(&id).Error
}

// RecentScans returns the host's newest scans (status, error message).
func (r *TelegramRepository) RecentScans(db *gorm.DB, hostID int64, n int) ([]entity.Scan, error) {
	var out []entity.Scan
	return out, db.Where("host_id = ?", hostID).Order("id DESC").Limit(n).Find(&out).Error
}

const componentGroups = `SELECT component_kind, component,
	SUM(severity = 'CRITICAL') AS critical, SUM(severity = 'HIGH') AS high
	FROM findings WHERE host_id = ? AND resolved_at IS NULL AND status = 'open'
	AND severity IN ('CRITICAL', 'HIGH') %s
	GROUP BY component_kind, component ORDER BY critical DESC, high DESC, component`

// NewInLastScan groups the open critical/high findings the host's last scan
// opened (ingest stamps first_seen with the host's last_scan_at).
func (r *TelegramRepository) NewInLastScan(db *gorm.DB, hostID int64) ([]entity.NewFindingGroup, error) {
	var out []entity.NewFindingGroup
	err := db.Raw(fmt.Sprintf(componentGroups, "AND first_seen = (SELECT last_scan_at FROM hosts WHERE id = findings.host_id)"), hostID).Scan(&out).Error
	return out, err
}

// OpenGroups groups every open critical/high finding of a host.
func (r *TelegramRepository) OpenGroups(db *gorm.DB, hostID int64) ([]entity.NewFindingGroup, error) {
	var out []entity.NewFindingGroup
	err := db.Raw(fmt.Sprintf(componentGroups, ""), hostID).Scan(&out).Error
	return out, err
}

// CVEHosts lists active hosts with an unresolved finding for cve.
func (r *TelegramRepository) CVEHosts(db *gorm.DB, cve string) ([]entity.CVEHost, error) {
	var out []entity.CVEHost
	err := db.Raw(`SELECT h.client_id, c.name AS client_name, h.hostname, f.pkg, f.severity,
		f.installed_version, f.fixed_version, f.status, COALESCE(f.note, '') AS note
		FROM findings f JOIN hosts h ON h.id = f.host_id JOIN clients c ON c.id = h.client_id
		WHERE f.cve = ? AND f.resolved_at IS NULL AND h.revoked_at IS NULL
		GROUP BY h.id, f.pkg, f.installed_version
		ORDER BY c.name, h.hostname`, cve).Scan(&out).Error
	return out, err
}

// ResolvedSince counts findings resolved after t, per client id.
func (r *TelegramRepository) ResolvedSince(db *gorm.DB, t any) (map[int64]int, error) {
	var rows []struct {
		ClientID int64
		N        int
	}
	err := db.Raw(`SELECT h.client_id, COUNT(*) AS n FROM findings f JOIN hosts h ON h.id = f.host_id
		WHERE f.resolved_at >= ? GROUP BY h.client_id`, t).Scan(&rows).Error
	out := map[int64]int{}
	for _, row := range rows {
		out[row.ClientID] = row.N
	}
	return out, err
}
