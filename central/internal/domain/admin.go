package domain

import (
	"fmt"
	"regexp"
	"time"
)

// AdminUser is a dashboard operator. Admins see every client.
type AdminUser struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	DisabledAt   *time.Time
}

func (u AdminUser) Active() bool { return u.DisabledAt == nil }

// Session is a logged-in dashboard session.
type Session struct {
	ID        int64
	UserID    int64
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
	// Current marks the caller's own session in a session list.
	Current bool
}

// SessionMeta is recorded at login so admins can recognise their sessions.
type SessionMeta struct {
	IP        string
	UserAgent string
}

var username = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func ValidateUsername(name string) error {
	if !username.MatchString(name) {
		return fmt.Errorf("%w: username %q must match %s", ErrInvalid, name, username)
	}
	return nil
}

// ValidatePassword enforces a minimum length; 72 bytes is bcrypt's input limit.
func ValidatePassword(p string) error {
	if len(p) < 12 || len(p) > 72 {
		return fmt.Errorf("%w: password must be 12-72 bytes", ErrInvalid)
	}
	return nil
}
