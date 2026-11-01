package repository

import (
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"netra-vuln/core/internal/entity"
)

type SoftwareRepository struct {
	Log *logrus.Logger
}

func NewSoftwareRepository(log *logrus.Logger) *SoftwareRepository {
	return &SoftwareRepository{Log: log}
}

// Replace sets the host's software to rows (already deduplicated per name and path).
func (r *SoftwareRepository) Replace(db *gorm.DB, hostID int64, rows []entity.Software) error {
	if err := db.Where("host_id = ?", hostID).Delete(&entity.Software{}).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	for i := range rows {
		rows[i].HostID = hostID
	}
	return db.CreateInBatches(rows, upsertBatch).Error
}

func (r *SoftwareRepository) DeleteByHost(db *gorm.DB, hostID int64) error {
	return db.Where("host_id = ?", hostID).Delete(&entity.Software{}).Error
}

// ByHost lists software per host id; hostID 0 = every host.
func (r *SoftwareRepository) ByHost(db *gorm.DB, hostID int64) (map[int64][]entity.Software, error) {
	var rows []entity.Software
	q := db.Order("host_id, name, path")
	if hostID != 0 {
		q = q.Where("host_id = ?", hostID)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := map[int64][]entity.Software{}
	for _, s := range rows {
		out[s.HostID] = append(out[s.HostID], s)
	}
	return out, nil
}

type EOLRepository struct {
	Log *logrus.Logger
}

func NewEOLRepository(log *logrus.Logger) *EOLRepository {
	return &EOLRepository{Log: log}
}

// ReplaceProduct swaps all cycles of one product.
func (r *EOLRepository) ReplaceProduct(db *gorm.DB, product string, cycles []entity.EOLCycle) error {
	if err := db.Where("product = ?", product).Delete(&entity.EOLCycle{}).Error; err != nil {
		return err
	}
	if len(cycles) == 0 {
		return nil
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(cycles, upsertBatch).Error
}

// All returns the cycles per product.
func (r *EOLRepository) All(db *gorm.DB) (map[string][]entity.EOLCycle, error) {
	var rows []entity.EOLCycle
	if err := db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string][]entity.EOLCycle{}
	for _, c := range rows {
		out[c.Product] = append(out[c.Product], c)
	}
	return out, nil
}
