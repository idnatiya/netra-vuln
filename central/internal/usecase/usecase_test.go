package usecase

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"netra-vuln/central/internal/domain"
)

// fakeStore implements only what the tests call; the embedded nil interface
// panics on anything else, which flags an unexpected call.
type fakeStore struct {
	Store
	clients     map[string]domain.Client
	enrollHash  []byte
	hosts       []domain.Host
	tokenHashes map[int64][]byte
	calls       []string
	seen        []time.Time
	failOn      string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		clients:     map[string]domain.Client{"client_a": {ID: 1, Name: "client_a"}},
		tokenHashes: map[int64][]byte{},
	}
}

func (f *fakeStore) call(name string) error {
	f.calls = append(f.calls, name)
	if f.failOn == name {
		return errors.New("boom")
	}
	return nil
}

func (f *fakeStore) InTx(_ context.Context, fn func(Store) error) error { return fn(f) }

func (f *fakeStore) ClientByName(_ context.Context, name string) (domain.Client, error) {
	c, ok := f.clients[name]
	if !ok {
		return c, domain.ErrNotFound
	}
	return c, nil
}
func (f *fakeStore) EnrollTokenValid(_ context.Context, _ int64, hash []byte) (bool, error) {
	return bytes.Equal(hash, f.enrollHash), nil
}
func (f *fakeStore) HostForUpdate(_ context.Context, clientID int64, hostname string) (domain.Host, error) {
	for _, h := range f.hosts {
		if h.ClientID == clientID && h.Hostname == hostname {
			return h, nil
		}
	}
	return domain.Host{}, domain.ErrNotFound
}
func (f *fakeStore) InsertHost(_ context.Context, clientID int64, hostname string, _ domain.HostMeta, hash []byte, _ time.Time) error {
	id := int64(len(f.hosts) + 1)
	f.hosts = append(f.hosts, domain.Host{ID: id, ClientID: clientID, Hostname: hostname})
	f.tokenHashes[id] = hash
	return f.call("InsertHost")
}
func (f *fakeStore) ReactivateHost(_ context.Context, id int64, _ domain.HostMeta, hash []byte) error {
	f.tokenHashes[id] = hash
	return f.call("ReactivateHost")
}
func (f *fakeStore) HostByTokenHash(_ context.Context, hash []byte) (domain.Host, error) {
	for id, h := range f.tokenHashes {
		if bytes.Equal(h, hash) {
			return domain.Host{ID: id, ClientName: "client_a", Hostname: "vm1"}, nil
		}
	}
	return domain.Host{}, domain.ErrNotFound
}
func (f *fakeStore) ListHosts(_ context.Context, _, hostname string) ([]domain.Host, error) {
	var out []domain.Host
	for _, h := range f.hosts {
		if h.Hostname == hostname {
			out = append(out, h)
		}
	}
	return out, nil
}
func (f *fakeStore) RevokeHost(context.Context, int64, time.Time) error { return f.call("RevokeHost") }
func (f *fakeStore) CreateClient(_ context.Context, name string, _ time.Time) (int64, error) {
	if _, ok := f.clients[name]; ok {
		return 0, domain.ErrConflict
	}
	f.clients[name] = domain.Client{ID: 99, Name: name}
	return 99, f.call("CreateClient")
}
func (f *fakeStore) InsertEnrollToken(_ context.Context, _ int64, hash []byte, _ time.Time) error {
	f.enrollHash = hash
	return f.call("InsertEnrollToken")
}
func (f *fakeStore) UpdateHostHeartbeat(context.Context, int64, domain.HostMeta, time.Time) error {
	return f.call("UpdateHostHeartbeat")
}
func (f *fakeStore) InsertScan(context.Context, int64, domain.Report, domain.Counts) error {
	return f.call("InsertScan")
}
func (f *fakeStore) UpsertFindings(_ context.Context, _ int64, _ []domain.Finding, seen time.Time) error {
	f.seen = append(f.seen, seen)
	return f.call("UpsertFindings")
}
func (f *fakeStore) ResolveMissing(_ context.Context, _ int64, seen time.Time) error {
	f.seen = append(f.seen, seen)
	return f.call("ResolveMissing")
}
func (f *fakeStore) UpdateHostScan(context.Context, int64, domain.Report, time.Time) error {
	return f.call("UpdateHostScan")
}

var clock = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC) }

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	tok, hash := NewToken()
	s.enrollHash = hash
	e := &Enroll{Store: s, Now: clock}
	req := domain.EnrollRequest{ClientName: "client_a", EnrollToken: tok, Hostname: "vm1"}

	hostTok, err := e.Run(ctx, req)
	if err != nil || len(hostTok) != 64 || !bytes.Equal(s.tokenHashes[1], HashToken(hostTok)) {
		t.Fatalf("enroll: tok=%q err=%v", hostTok, err)
	}
	if _, err := e.Run(ctx, req); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("active host: err = %v", err)
	}

	revoked := clock()
	s.hosts[0].RevokedAt = &revoked
	newTok, err := e.Run(ctx, req)
	if err != nil || newTok == hostTok || !slices.Contains(s.calls, "ReactivateHost") {
		t.Fatalf("reactivate: err=%v calls=%v", err, s.calls)
	}

	for name, r := range map[string]domain.EnrollRequest{
		"bad token":      {ClientName: "client_a", EnrollToken: "nope", Hostname: "vm2"},
		"unknown client": {ClientName: "client_x", EnrollToken: tok, Hostname: "vm2"},
	} {
		if _, err := e.Run(ctx, r); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := e.Run(ctx, domain.EnrollRequest{ClientName: "client_a", EnrollToken: tok}); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("empty hostname: err = %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	s := newFakeStore()
	tok, hash := NewToken()
	s.tokenHashes[7] = hash
	a := &Agent{Store: s, Now: clock}
	if h, err := a.Authenticate(context.Background(), tok); err != nil || h.ID != 7 {
		t.Fatalf("h=%+v err=%v", h, err)
	}
	for _, bad := range []string{"", "wrong"} {
		if _, err := a.Authenticate(context.Background(), bad); !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func report(status domain.ScanStatus) domain.Report {
	return domain.Report{
		ClientName: "client_a", Hostname: "vm1", Status: status, ScannedAt: clock(),
		Findings: []domain.Finding{{CVE: "CVE-1", Pkg: "openssl", Severity: "HIGH"}},
	}
}

func TestIngest(t *testing.T) {
	host := domain.Host{ID: 1, ClientName: "client_a", Hostname: "vm1"}
	tests := []struct {
		name      string
		r         domain.Report
		wantErr   error
		wantCalls []string
	}{
		{"ok", report(domain.StatusOK), nil, []string{"InsertScan", "UpsertFindings", "ResolveMissing", "UpdateHostScan"}},
		{"error scan leaves findings alone", report(domain.StatusError), nil, []string{"InsertScan", "UpdateHostScan"}},
		{"other client", func() domain.Report { r := report(domain.StatusOK); r.ClientName = "client_b"; return r }(), domain.ErrForbidden, nil},
		{"other hostname", func() domain.Report { r := report(domain.StatusOK); r.Hostname = "vm2"; return r }(), domain.ErrForbidden, nil},
		{"invalid", func() domain.Report { r := report(domain.StatusOK); r.Status = "weird"; return r }(), domain.ErrInvalid, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFakeStore()
			err := (&Agent{Store: s, Now: clock}).Ingest(context.Background(), host, tt.r)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !slices.Equal(s.calls, tt.wantCalls) {
				t.Fatalf("calls = %v, want %v", s.calls, tt.wantCalls)
			}
		})
	}
}

func TestIngestUsesOneMicrosecondTimestamp(t *testing.T) {
	s := newFakeStore()
	host := domain.Host{ID: 1, ClientName: "client_a", Hostname: "vm1"}
	if err := (&Agent{Store: s, Now: clock}).Ingest(context.Background(), host, report(domain.StatusOK)); err != nil {
		t.Fatal(err)
	}
	if len(s.seen) != 2 || !s.seen[0].Equal(s.seen[1]) || s.seen[0].Nanosecond()%1000 != 0 {
		t.Fatalf("seen = %v", s.seen)
	}
}

func TestIngestErrorRollsBack(t *testing.T) {
	s := newFakeStore()
	s.failOn = "UpsertFindings"
	host := domain.Host{ID: 1, ClientName: "client_a", Hostname: "vm1"}
	if err := (&Agent{Store: s, Now: clock}).Ingest(context.Background(), host, report(domain.StatusOK)); err == nil {
		t.Fatal("want error")
	}
	if slices.Contains(s.calls, "UpdateHostScan") {
		t.Fatal("continued after failure")
	}
}

func TestHeartbeatTenant(t *testing.T) {
	s := newFakeStore()
	a := &Agent{Store: s, Now: clock}
	host := domain.Host{ID: 1, ClientName: "client_a", Hostname: "vm1"}
	if err := a.Heartbeat(context.Background(), host, "client_b", "vm1", domain.HostMeta{}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
	if err := a.Heartbeat(context.Background(), host, "client_a", "vm1", domain.HostMeta{}); err != nil {
		t.Fatal(err)
	}
}

func TestAdmin(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	a := &Admin{Store: s, Now: clock}

	tok, err := a.CreateClient(ctx, "client_b")
	if err != nil || !bytes.Equal(s.enrollHash, HashToken(tok)) {
		t.Fatalf("create: %v", err)
	}
	if _, err := a.CreateClient(ctx, "Bad Name"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}
	if _, err := a.CreateClient(ctx, "client_b"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}

	revoked := clock()
	s.hosts = []domain.Host{
		{ID: 1, ClientID: 1, Hostname: "web"},
		{ID: 2, ClientID: 2, Hostname: "web"},
		{ID: 3, ClientID: 1, Hostname: "old", RevokedAt: &revoked},
	}
	if _, err := a.RevokeHost(ctx, "web", ""); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := a.RevokeHost(ctx, "old", ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("already revoked: %v", err)
	}
	s.hosts = s.hosts[:1]
	if h, err := a.RevokeHost(ctx, "web", ""); err != nil || h.ID != 1 {
		t.Fatalf("revoke: %+v %v", h, err)
	}
}
