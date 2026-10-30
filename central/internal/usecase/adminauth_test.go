package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"netra-vuln/central/internal/domain"
)

type fakeSession struct {
	id      int64
	userID  int64
	expires time.Time
	meta    domain.SessionMeta
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
func (f *adminFake) InTx(_ context.Context, fn func(Store) error) error { return fn(f) }
func (f *adminFake) InsertSession(_ context.Context, uid int64, hash []byte, meta domain.SessionMeta, _, exp time.Time) error {
	f.sessions[string(hash)] = fakeSession{int64(len(f.sessions) + 1), uid, exp, meta}
	return nil
}
func (f *adminFake) SessionByTokenHash(_ context.Context, hash []byte, now time.Time) (domain.Session, error) {
	s, ok := f.sessions[string(hash)]
	if !ok || !s.expires.After(now) {
		return domain.Session{}, domain.ErrNotFound
	}
	username := ""
	for _, u := range f.users {
		if u.ID == s.userID {
			username = u.Username
		}
	}
	return domain.Session{ID: s.id, UserID: s.userID, Username: username, ExpiresAt: s.expires, IP: s.meta.IP, UserAgent: s.meta.UserAgent}, nil
}
func (f *adminFake) ListSessions(_ context.Context, uid int64, now time.Time) ([]domain.Session, error) {
	var out []domain.Session
	for _, s := range f.sessions {
		if s.userID == uid && s.expires.After(now) {
			out = append(out, domain.Session{ID: s.id, UserID: s.userID, ExpiresAt: s.expires})
		}
	}
	return out, nil
}
func (f *adminFake) DeleteSessionByID(_ context.Context, uid, id int64) error {
	for k, s := range f.sessions {
		if s.id == id && s.userID == uid {
			delete(f.sessions, k)
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *adminFake) DeleteOtherSessions(_ context.Context, uid, keep int64) (int, error) {
	n := 0
	for k, s := range f.sessions {
		if s.userID == uid && s.id != keep {
			delete(f.sessions, k)
			n++
		}
	}
	return n, nil
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
		if _, _, err := a.Login(ctx, c[0], c[1], domain.SessionMeta{}); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("login %v: %v", c, err)
		}
	}

	disabled := cur
	st.users["off"] = domain.AdminUser{ID: 9, Username: "off", PasswordHash: st.users["ops"].PasswordHash, DisabledAt: &disabled}
	if _, _, err := a.Login(ctx, "off", "correct horse battery", domain.SessionMeta{}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("disabled user: %v", err)
	}

	tok, sess, err := a.Login(ctx, "ops", "correct horse battery", domain.SessionMeta{})
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

	tok, _, _ = a.Login(ctx, "ops", "correct horse battery", domain.SessionMeta{})
	a.Logout(ctx, tok)
	if _, err := a.Session(ctx, tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("after logout: %v", err)
	}

	if err := a.SetPassword(ctx, "ops", "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login(ctx, "ops", "correct horse battery", domain.SessionMeta{}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("old password still works")
	}
}

func TestAccountSessions(t *testing.T) {
	ctx := context.Background()
	st := newAdminFake()
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &AdminAuth{Store: st, Now: func() time.Time { return cur }, Cost: bcrypt.MinCost}
	if err := a.CreateAdmin(ctx, "ops", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateAdmin(ctx, "eve", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	ua := strings.Repeat("é", 200) // 400 bytes
	tok1, _, _ := a.Login(ctx, "ops", "correct horse battery", domain.SessionMeta{IP: "100.64.0.7", UserAgent: ua})
	tok2, _, _ := a.Login(ctx, "ops", "correct horse battery", domain.SessionMeta{})
	tokEve, _, _ := a.Login(ctx, "eve", "correct horse battery", domain.SessionMeta{})
	me, _ := a.Session(ctx, tok1)
	if len(me.UserAgent) > 255 || !utf8.ValidString(me.UserAgent) || me.IP != "100.64.0.7" {
		t.Fatalf("meta not truncated cleanly: %d bytes, ip %q", len(me.UserAgent), me.IP)
	}
	eve, _ := a.Session(ctx, tokEve)

	list, err := a.ListSessions(ctx, me)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %+v %v", list, err)
	}
	for _, s := range list {
		if s.Current != (s.ID == me.ID) {
			t.Fatalf("current flag: %+v", s)
		}
	}
	if err := a.RevokeSession(ctx, me, me.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("revoke current: %v", err)
	}
	if err := a.RevokeSession(ctx, me, eve.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke another admin's session: %v", err)
	}

	if _, err := a.ChangePassword(ctx, me, "wrong password!!", "brand new passphrase"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("wrong current: %v", err)
	}
	if _, err := a.ChangePassword(ctx, me, "correct horse battery", "short"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("short new: %v", err)
	}
	n, err := a.ChangePassword(ctx, me, "correct horse battery", "brand new passphrase")
	if err != nil || n != 1 {
		t.Fatalf("change: n=%d %v", n, err)
	}
	if _, err := a.Session(ctx, tok2); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("other session survived the password change")
	}
	if _, err := a.Session(ctx, tok1); err != nil {
		t.Fatalf("current session ended: %v", err)
	}
	if _, err := a.Session(ctx, tokEve); err != nil {
		t.Fatalf("another admin was signed out: %v", err)
	}
	if _, _, err := a.Login(ctx, "ops", "brand new passphrase", domain.SessionMeta{}); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if n, err := a.RevokeOtherSessions(ctx, me); err != nil || n != 1 {
		t.Fatalf("revoke others: %d %v", n, err)
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
