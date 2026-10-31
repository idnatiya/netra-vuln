package repository

import (
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"netra-vuln/core/internal/entity"
)

type AdminUserRepository struct {
	Repository[entity.AdminUser]
	Log *logrus.Logger
}

func NewAdminUserRepository(log *logrus.Logger) *AdminUserRepository {
	return &AdminUserRepository{Log: log}
}

func (r *AdminUserRepository) FindByUsername(db *gorm.DB, user *entity.AdminUser, username string) error {
	return db.Where("username = ?", username).Take(user).Error
}

func (r *AdminUserRepository) FindAll(db *gorm.DB) ([]entity.AdminUser, error) {
	var users []entity.AdminUser
	err := db.Order("username").Find(&users).Error
	return users, err
}

func (r *AdminUserRepository) UpdatePassword(db *gorm.DB, userID int64, passwordHash string) error {
	return db.Model(&entity.AdminUser{}).Where("id = ?", userID).Update("password_hash", passwordHash).Error
}

type AdminSessionRepository struct {
	Repository[entity.AdminSession]
	Log *logrus.Logger
}

func NewAdminSessionRepository(log *logrus.Logger) *AdminSessionRepository {
	return &AdminSessionRepository{Log: log}
}

// FindActiveByTokenHash loads an unexpired session of an active admin, with the admin.
func (r *AdminSessionRepository) FindActiveByTokenHash(db *gorm.DB, s *entity.AdminSession, hash []byte, now time.Time) error {
	return db.Joins("User").
		Where("admin_sessions.token_hash = ? AND admin_sessions.expires_at > ? AND User.disabled_at IS NULL", hash, now).
		Take(s).Error
}

// FindActiveByUser lists a user's unexpired sessions, newest first.
func (r *AdminSessionRepository) FindActiveByUser(db *gorm.DB, userID int64, now time.Time) ([]entity.AdminSession, error) {
	var out []entity.AdminSession
	err := db.Where("user_id = ? AND expires_at > ?", userID, now).Order("created_at DESC, id DESC").Find(&out).Error
	return out, err
}

func (r *AdminSessionRepository) DeleteByTokenHash(db *gorm.DB, hash []byte) error {
	return db.Where("token_hash = ?", hash).Delete(&entity.AdminSession{}).Error
}

// DeleteByUserAndId deletes one session of a user and returns how many rows went.
func (r *AdminSessionRepository) DeleteByUserAndId(db *gorm.DB, userID, id int64) (int64, error) {
	res := db.Where("id = ? AND user_id = ?", id, userID).Delete(&entity.AdminSession{})
	return res.RowsAffected, res.Error
}

// DeleteOthers deletes every session of the user except keepID and returns how many.
func (r *AdminSessionRepository) DeleteOthers(db *gorm.DB, userID, keepID int64) (int64, error) {
	res := db.Where("user_id = ? AND id <> ?", userID, keepID).Delete(&entity.AdminSession{})
	return res.RowsAffected, res.Error
}

func (r *AdminSessionRepository) DeleteExpired(db *gorm.DB, now time.Time) error {
	return db.Where("expires_at <= ?", now).Delete(&entity.AdminSession{}).Error
}

type McpTokenRepository struct {
	Repository[entity.McpToken]
	Log *logrus.Logger
}

func NewMcpTokenRepository(log *logrus.Logger) *McpTokenRepository {
	return &McpTokenRepository{Log: log}
}

// FindActiveByTokenHash loads an unrevoked token of an active admin, with the admin.
func (r *McpTokenRepository) FindActiveByTokenHash(db *gorm.DB, t *entity.McpToken, hash []byte) error {
	return db.Joins("User").
		Where("mcp_tokens.token_hash = ? AND mcp_tokens.revoked_at IS NULL AND User.disabled_at IS NULL", hash).
		Take(t).Error
}

// FindActiveByUser lists a user's unrevoked tokens, newest first.
func (r *McpTokenRepository) FindActiveByUser(db *gorm.DB, userID int64) ([]entity.McpToken, error) {
	var out []entity.McpToken
	err := db.Where("user_id = ? AND revoked_at IS NULL", userID).Order("created_at DESC, id DESC").Find(&out).Error
	return out, err
}

func (r *McpTokenRepository) TouchLastUsed(db *gorm.DB, id int64, at time.Time) error {
	return db.Model(&entity.McpToken{}).Where("id = ?", id).Update("last_used_at", at).Error
}

// Revoke revokes one unrevoked token of a user and returns how many rows changed.
func (r *McpTokenRepository) Revoke(db *gorm.DB, userID, id int64, at time.Time) (int64, error) {
	res := db.Model(&entity.McpToken{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).Update("revoked_at", at)
	return res.RowsAffected, res.Error
}
