package model

import "time"

// Auth is the signed-in admin, set in Locals by the session middleware.
type Auth struct {
	SessionID int64
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

type LoginUserRequest struct {
	Username  string `json:"username" validate:"required,max=64"`
	Password  string `json:"password" validate:"required,max=72"`
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

// MeResponse is the current session, returned by login and /me.
type MeResponse struct {
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=72"`
	NewPassword     string `json:"new_password" validate:"required,min=12,max=72"`
}

type SessionResponse struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

type RevokeSessionRequest struct {
	ID int64 `json:"-" validate:"required,min=1"`
}

// CreateAdminRequest and SetPasswordRequest back the `central admin` CLI.
type CreateAdminRequest struct {
	Username string `validate:"required,username"`
	Password string `validate:"required,min=12,max=72"`
}

type AdminUserResponse struct {
	Username   string     `json:"username"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
}

type CreateMcpTokenRequest struct {
	Name string `json:"name" validate:"required,max=64"`
}

type McpTokenResponse struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// CreateMcpTokenResponse carries the plaintext token; it is shown once.
type CreateMcpTokenResponse struct {
	McpTokenResponse
	Token string `json:"token"`
}

type RevokeMcpTokenRequest struct {
	ID int64 `json:"-" validate:"required,min=1"`
}
