package entity

import (
	"regexp"
	"time"
)

// AdminUser is a dashboard operator. Admins see every client.
type AdminUser struct {
	ID           int64      `gorm:"column:id;primaryKey"`
	Username     string     `gorm:"column:username"`
	PasswordHash string     `gorm:"column:password_hash"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	DisabledAt   *time.Time `gorm:"column:disabled_at"`
}

func (u *AdminUser) TableName() string { return "admin_users" }

func (u *AdminUser) Active() bool { return u.DisabledAt == nil }

// AdminSession is a logged-in dashboard session; only the token hash is stored.
type AdminSession struct {
	ID        int64     `gorm:"column:id;primaryKey"`
	UserID    int64     `gorm:"column:user_id"`
	TokenHash []byte    `gorm:"column:token_hash"`
	IP        string    `gorm:"column:ip"`
	UserAgent string    `gorm:"column:user_agent"`
	CreatedAt time.Time `gorm:"column:created_at"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	User      AdminUser `gorm:"foreignKey:UserID;references:ID"`
}

func (s *AdminSession) TableName() string { return "admin_sessions" }

// UsernamePattern is what an admin username must match (validator tag "username").
var UsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// Password limits; 72 bytes is bcrypt's input limit.
const (
	MinPasswordBytes = 12
	MaxPasswordBytes = 72
)
