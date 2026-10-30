// Package entity holds central's tables (GORM models) and pure business rules.
package entity

import (
	"regexp"
	"time"
)

type Client struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name"`
	// ScanConfig holds per-client scan overrides in the wire.ScanConfig JSON
	// format (validated before storing); nil = agent defaults.
	ScanConfig []byte    `gorm:"column:scan_config"`
	CreatedAt  time.Time `gorm:"column:created_at"`
}

func (c *Client) TableName() string { return "clients" }

// ClientNamePattern is what a client name must match (validator tag "clientname").
var ClientNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type EnrollToken struct {
	ID        int64      `gorm:"column:id;primaryKey"`
	ClientID  int64      `gorm:"column:client_id"`
	TokenHash []byte     `gorm:"column:token_hash"`
	CreatedAt time.Time  `gorm:"column:created_at"`
	RevokedAt *time.Time `gorm:"column:revoked_at"`
}

func (t *EnrollToken) TableName() string { return "enroll_tokens" }
