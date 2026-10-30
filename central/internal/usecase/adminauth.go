package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
func (a *AdminAuth) Login(ctx context.Context, username, password string, meta domain.SessionMeta) (string, domain.Session, error) {
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
	meta = domain.SessionMeta{IP: truncate(meta.IP, 45), UserAgent: truncate(meta.UserAgent, 255)}
	s := domain.Session{UserID: u.ID, Username: u.Username, CreatedAt: t, ExpiresAt: t.Add(ttl), IP: meta.IP, UserAgent: meta.UserAgent}
	if err := a.Store.DeleteExpiredSessions(ctx, t); err != nil {
		return "", s, err
	}
	if err := a.Store.InsertSession(ctx, u.ID, hash, meta, t, s.ExpiresAt); err != nil {
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

// ChangePassword sets a new password for the signed-in admin after checking the
// current one, then signs out every other session of that admin. A wrong
// current password is ErrInvalid, not ErrUnauthorized: the session stays valid.
func (a *AdminAuth) ChangePassword(ctx context.Context, sess domain.Session, current, next string) (int, error) {
	u, err := a.Store.AdminUserByUsername(ctx, sess.Username)
	if err != nil {
		return 0, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil {
		return 0, fmt.Errorf("%w: current password is wrong", domain.ErrInvalid)
	}
	if current == next {
		return 0, fmt.Errorf("%w: the new password must differ from the current one", domain.ErrInvalid)
	}
	hash, err := a.hash(u.Username, next)
	if err != nil {
		return 0, err
	}
	var n int
	err = a.Store.InTx(ctx, func(st Store) error {
		if err := st.SetAdminPassword(ctx, u.Username, hash); err != nil {
			return err
		}
		n, err = st.DeleteOtherSessions(ctx, u.ID, sess.ID)
		return err
	})
	return n, err
}

// ListSessions returns the admin's active sessions with the caller's own marked Current.
func (a *AdminAuth) ListSessions(ctx context.Context, sess domain.Session) ([]domain.Session, error) {
	list, err := a.Store.ListSessions(ctx, sess.UserID, now(a.Now))
	for i := range list {
		list[i].Current = list[i].ID == sess.ID
	}
	return list, err
}

// RevokeSession signs out one of the admin's other sessions; the current one
// is ended with Logout instead (ErrConflict).
func (a *AdminAuth) RevokeSession(ctx context.Context, sess domain.Session, id int64) error {
	if id == sess.ID {
		return fmt.Errorf("%w: this is the current session; sign out instead", domain.ErrConflict)
	}
	return a.Store.DeleteSessionByID(ctx, sess.UserID, id)
}

// RevokeOtherSessions signs out every session of the admin except the caller's.
func (a *AdminAuth) RevokeOtherSessions(ctx context.Context, sess domain.Session) (int, error) {
	return a.Store.DeleteOtherSessions(ctx, sess.UserID, sess.ID)
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

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
