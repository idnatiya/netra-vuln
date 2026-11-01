package repository

import (
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
)

type ClientRepository struct {
	Repository[entity.Client]
	Log *logrus.Logger
}

func NewClientRepository(log *logrus.Logger) *ClientRepository {
	return &ClientRepository{Log: log}
}

func (r *ClientRepository) FindByName(db *gorm.DB, client *entity.Client, name string) error {
	return db.Where("name = ?", name).Take(client).Error
}

func (r *ClientRepository) FindByNameForUpdate(db *gorm.DB, client *entity.Client, name string) error {
	return db.Where("name = ?", name).Take(client).Error // write-locked by BEGIN IMMEDIATE
}

func (r *ClientRepository) FindAll(db *gorm.DB) ([]entity.Client, error) {
	var clients []entity.Client
	err := db.Order("name").Find(&clients).Error
	return clients, err
}

// UpdateScanConfig stores cfg (wire.ScanConfig JSON); nil writes NULL.
func (r *ClientRepository) UpdateScanConfig(db *gorm.DB, clientID int64, cfg []byte) error {
	var v any
	if cfg != nil {
		v = string(cfg)
	}
	return db.Model(&entity.Client{}).Where("id = ?", clientID).Update("scan_config", v).Error
}

type EnrollTokenRepository struct {
	Repository[entity.EnrollToken]
	Log *logrus.Logger
}

func NewEnrollTokenRepository(log *logrus.Logger) *EnrollTokenRepository {
	return &EnrollTokenRepository{Log: log}
}

func (r *EnrollTokenRepository) CountValid(db *gorm.DB, clientID int64, hash []byte) (int64, error) {
	var n int64
	err := db.Model(&entity.EnrollToken{}).
		Where("client_id = ? AND token_hash = ? AND revoked_at IS NULL", clientID, hash).Count(&n).Error
	return n, err
}

// Consume atomically claims a token; the enclosing transaction rolls back on enrollment failure.
func (r *EnrollTokenRepository) Consume(db *gorm.DB, clientID int64, hash []byte, now time.Time) (bool, error) {
	result := db.Model(&entity.EnrollToken{}).Where("client_id = ? AND token_hash = ? AND revoked_at IS NULL", clientID, hash).Update("revoked_at", now)
	return result.RowsAffected == 1, result.Error
}

// RevokeAll revokes every active enroll token of a client.
func (r *EnrollTokenRepository) RevokeAll(db *gorm.DB, clientID int64, now time.Time) error {
	return db.Model(&entity.EnrollToken{}).Where("client_id = ? AND revoked_at IS NULL", clientID).
		Update("revoked_at", now).Error
}
