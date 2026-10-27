package usecase

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netra-vuln/central/internal/domain"
)

const DefaultSessionTTL = 12 * time.Hour

// AdminAuth handles dashboard admins and their sessions.
type AdminAuth struct {
	Store      Store
	Now        func() time.Time
	SessionTTL time.Duration // 0 = DefaultSessionTTL
	Cost       int           // bcrypt cost; 0 = bcrypt.DefaultCost (tests lower it)
}

func (a *AdminAuth) cost() int {
	if a.Cost == 0 {
		return bcrypt.DefaultCost
	}
	return a.Cost
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

// Login returns a new session token. Every failure is ErrUnauthorized, and an
// unknown user still pays for one bcrypt comparison so timing does not reveal
// which usernames exist.
func (a *AdminAuth) Login(ctx context.Context, username, password string) (string, domain.Session, error) {
	u, err := a.Store.AdminUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return "", domain.Session{}, err
	}
	if err != nil || !u.Active() {
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), a.cost()) })
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return "", domain.Session{}, domain.ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", domain.Session{}, domain.ErrUnauthorized
	}

	t := now(a.Now)
	ttl := a.SessionTTL
	if ttl == 0 {
		ttl = DefaultSessionTTL
	}
	token, hash := NewToken()
	s := domain.Session{UserID: u.ID, Username: u.Username, ExpiresAt: t.Add(ttl)}
	if err := a.Store.DeleteExpiredSessions(ctx, t); err != nil {
		return "", s, err
	}
	if err := a.Store.InsertSession(ctx, u.ID, hash, t, s.ExpiresAt); err != nil {
		return "", s, err
	}
	return token, s, nil
}

func (a *AdminAuth) Session(ctx context.Context, token string) (domain.Session, error) {
	if token == "" {
		return domain.Session{}, domain.ErrUnauthorized
	}
	s, err := a.Store.SessionByTokenHash(ctx, HashToken(token), now(a.Now))
	if errors.Is(err, domain.ErrNotFound) {
		return s, domain.ErrUnauthorized
	}
	return s, err
}

func (a *AdminAuth) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return a.Store.DeleteSession(ctx, HashToken(token))
}

func (a *AdminAuth) CreateAdmin(ctx context.Context, username, password string) error {
	hash, err := a.hash(username, password)
	if err != nil {
		return err
	}
	return a.Store.CreateAdminUser(ctx, username, hash, now(a.Now))
}

func (a *AdminAuth) SetPassword(ctx context.Context, username, password string) error {
	hash, err := a.hash(username, password)
	if err != nil {
		return err
	}
	if _, err := a.Store.AdminUserByUsername(ctx, username); err != nil {
		return fmt.Errorf("admin %q: %w", username, err)
	}
	return a.Store.SetAdminPassword(ctx, username, hash)
}

func (a *AdminAuth) ListAdmins(ctx context.Context) ([]domain.AdminUser, error) {
	return a.Store.ListAdminUsers(ctx)
}

func (a *AdminAuth) hash(username, password string) (string, error) {
	if err := domain.ValidateUsername(username); err != nil {
		return "", err
	}
	if err := domain.ValidatePassword(password); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), a.cost())
	return string(h), err
}
