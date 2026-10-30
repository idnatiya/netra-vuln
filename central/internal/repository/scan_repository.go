package repository

import (
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/central/internal/entity"
)

type ScanRepository struct {
	Repository[entity.Scan]
	Log *logrus.Logger
}

func NewScanRepository(log *logrus.Logger) *ScanRepository {
	return &ScanRepository{Log: log}
}

// Trend sums, per UTC day, the last successful scan of each active host that day.
// ponytail: a host that skipped a day simply drops out of that day's sum; the
// dashboard carries the previous value forward for sparklines.
func (r *ScanRepository) Trend(db *gorm.DB, clientName string, hostID int64, since time.Time) ([]entity.TrendPoint, error) {
	out := []entity.TrendPoint{}
	err := db.Raw(`WITH daily AS (
			SELECT DATE(sc.scanned_at) AS day, sc.critical, sc.high,
				ROW_NUMBER() OVER (PARTITION BY sc.host_id, DATE(sc.scanned_at) ORDER BY sc.scanned_at DESC) AS rn
			FROM scans sc
			JOIN hosts h ON h.id = sc.host_id
			JOIN clients c ON c.id = h.client_id
			WHERE sc.status = 'ok' AND sc.scanned_at >= ? AND h.revoked_at IS NULL
				AND (? = '' OR c.name = ?) AND (? = 0 OR h.id = ?)
		)
		SELECT day, SUM(critical) AS critical, SUM(high) AS high FROM daily WHERE rn = 1 GROUP BY day ORDER BY day`,
		since, clientName, clientName, hostID, hostID).Scan(&out).Error
	return out, err
}
