package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netra-vuln/central/internal/domain"
)

type fakeSession struct {
	userID  int64
	expires time.Time
}

// admin methods on the shared fakeStore (see usecase_test.go).
type adminFake struct {
	*fakeStore
	users    map[string]domain.AdminUser
	sessions map[string]fakeSession
	triaged  []domain.TriageStatus
}

func newAdminFake() *adminFake {
	return &adminFake{fakeStore: newFakeStore(), users: map[string]domain.AdminUser{}, sessions: map[string]fakeSession{}}
}

func (f *adminFake) CreateAdminUser(_ context.Context, u, hash string, _ time.Time) error {
	if _, ok := f.users[u]; ok {
		return domain.ErrConflict
	}
	f.users[u] = domain.AdminUser{ID: int64(len(f.users) + 1), Username: u, PasswordHash: hash}
	return nil
}
func (f *adminFake) AdminUserByUsername(_ context.Context, u string) (domain.AdminUser, error) {
	if x, ok := f.users[u]; ok {
		return x, nil
	}
	return domain.AdminUser{}, domain.ErrNotFound
}
func (f *adminFake) SetAdminPassword(_ context.Context, u, hash string) error {
	x := f.users[u]
	x.PasswordHash = hash
	f.users[u] = x
	return nil
}
func (f *adminFake) InsertSession(_ context.Context, uid int64, hash []byte, _, exp time.Time) error {
	f.sessions[string(hash)] = fakeSession{uid, exp}
	return nil
}
func (f *adminFake) SessionByTokenHash(_ context.Context, hash []byte, now time.Time) (domain.Session, error) {
	s, ok := f.sessions[string(hash)]
	if !ok || !s.expires.After(now) {
		return domain.Session{}, domain.ErrNotFound
	}
	return domain.Session{UserID: s.userID, ExpiresAt: s.expires}, nil
}
func (f *adminFake) DeleteSession(_ context.Context, hash []byte) error {
	delete(f.sessions, string(hash))
	return nil
}
func (f *adminFake) DeleteExpiredSessions(context.Context, time.Time) error { return nil }
func (f *adminFake) UpdateFindingTriage(_ context.Context, id int64, s domain.TriageStatus, _ string) error {
	if id != 1 {
		return domain.ErrNotFound
	}
	f.triaged = append(f.triaged, s)
	return nil
}

func TestAdminAuth(t *testing.T) {
	ctx := context.Background()
	st := newAdminFake()
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &AdminAuth{Store: st, Now: func() time.Time { return cur }, Cost: bcrypt.MinCost}

	if err := a.CreateAdmin(ctx, "ops", "short"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("short password: %v", err)
	}
	if err := a.CreateAdmin(ctx, "ops", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if st.users["ops"].PasswordHash == "correct horse battery" {
		t.Fatal("password stored in plaintext")
	}

	for _, c := range [][2]string{{"ops", "wrong password!!"}, {"nobody", "correct horse battery"}} {
		if _, _, err := a.Login(ctx, c[0], c[1]); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("login %v: %v", c, err)
		}
	}

	disabled := cur
	st.users["off"] = domain.AdminUser{ID: 9, Username: "off", PasswordHash: st.users["ops"].PasswordHash, DisabledAt: &disabled}
	if _, _, err := a.Login(ctx, "off", "correct horse battery"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("disabled user: %v", err)
	}

	tok, sess, err := a.Login(ctx, "ops", "correct horse battery")
	if err != nil || len(tok) != 64 || !sess.ExpiresAt.Equal(cur.Add(DefaultSessionTTL)) {
		t.Fatalf("login: %q %+v %v", tok, sess, err)
	}
	if _, err := a.Session(ctx, tok); err != nil {
		t.Fatalf("session: %v", err)
	}
	cur = cur.Add(DefaultSessionTTL + time.Second)
	if _, err := a.Session(ctx, tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expired session: %v", err)
	}

	tok, _, _ = a.Login(ctx, "ops", "correct horse battery")
	a.Logout(ctx, tok)
	if _, err := a.Session(ctx, tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("after logout: %v", err)
	}

	if err := a.SetPassword(ctx, "ops", "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login(ctx, "ops", "correct horse battery"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("old password still works")
	}
}

func TestTriageFinding(t *testing.T) {
	st := newAdminFake()
	d := &Dashboard{Store: st, Now: clock}
	ctx := context.Background()
	if err := d.TriageFinding(ctx, 1, domain.TriageAccepted, "risk accepted until Q3"); err != nil {
		t.Fatal(err)
	}
	if err := d.TriageFinding(ctx, 1, "fixed", ""); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
	if err := d.TriageFinding(ctx, 1, domain.TriageOpen, string(make([]byte, domain.MaxNoteLength+1))); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("long note: %v", err)
	}
	if err := d.TriageFinding(ctx, 2, domain.TriageOpen, ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if len(st.triaged) != 1 {
		t.Fatalf("triaged = %v", st.triaged)
	}
}
