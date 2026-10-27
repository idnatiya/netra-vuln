package mysql_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/adapter/httpapi"
	"netra-vuln/central/internal/adapter/mysql"
	"netra-vuln/central/internal/adapter/mysql/mysqltest"
	"netra-vuln/central/internal/domain"
	"netra-vuln/central/internal/usecase"
	"netra-vuln/internal/wire"
	"netra-vuln/migrations"
)

// env wires real usecases to a fresh database with a controllable clock.
type env struct {
	db     *sql.DB
	store  *mysql.Store
	admin  *usecase.Admin
	enroll *usecase.Enroll
	agent  *usecase.Agent
	now    time.Time
}

func newEnv(t *testing.T) *env {
	db := mysqltest.Open(t)
	e := &env{db: db, store: mysql.New(db), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return e.now }
	e.admin = &usecase.Admin{Store: e.store, Now: clock}
	e.enroll = &usecase.Enroll{Store: e.store, Now: clock}
	e.agent = &usecase.Agent{Store: e.store, Now: clock}
	return e
}

func (e *env) tick() { e.now = e.now.Add(time.Hour) }

// enrollHost creates the client if needed and enrolls hostname, returning the
// authenticated host and its token.
func (e *env) enrollHost(t *testing.T, client, hostname string) (domain.Host, string) {
	t.Helper()
	ctx := context.Background()
	enrollTok, err := e.admin.CreateClient(ctx, client) // one host per client in these tests
	if err != nil {
		t.Fatal(err)
	}
	hostTok, err := e.enroll.Run(ctx, domain.EnrollRequest{ClientName: client, EnrollToken: enrollTok, Hostname: hostname})
	if err != nil {
		t.Fatal(err)
	}
	h, err := e.agent.Authenticate(ctx, hostTok)
	if err != nil {
		t.Fatal(err)
	}
	return h, hostTok
}

func finding(cve string) domain.Finding {
	return domain.Finding{Target: "vm (ubuntu 24.04)", Type: "ubuntu", CVE: cve, Pkg: "openssl",
		InstalledVersion: "3.0.1", FixedVersion: "3.0.2", Severity: "HIGH", Title: "t"}
}

func (e *env) ingest(t *testing.T, h domain.Host, status domain.ScanStatus, cves ...string) {
	t.Helper()
	r := domain.Report{ClientName: h.ClientName, Hostname: h.Hostname, Status: status, ScannedAt: e.now, TrivyVersion: "0.72.0"}
	for _, c := range cves {
		r.Findings = append(r.Findings, finding(c))
	}
	if status == domain.StatusError {
		r.Error = "trivy: boom"
	}
	if err := e.agent.Ingest(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
}

type row struct {
	firstSeen, lastSeen time.Time
	resolved            *time.Time
}

func (e *env) findings(t *testing.T, hostID int64) map[string]row {
	t.Helper()
	rows, err := e.db.Query(`SELECT cve, first_seen, last_seen, resolved_at FROM findings WHERE host_id = ?`, hostID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]row{}
	for rows.Next() {
		var cve string
		var r row
		var resolved sql.NullTime
		if err := rows.Scan(&cve, &r.firstSeen, &r.lastSeen, &resolved); err != nil {
			t.Fatal(err)
		}
		if resolved.Valid {
			r.resolved = &resolved.Time
		}
		out[cve] = r
	}
	return out
}

func (e *env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrateIdempotent(t *testing.T) {
	e := newEnv(t)
	mysqltest.MigrateAgain(t, e.db)
	files, _ := fs.Glob(migrations.FS, "*.sql")
	if n := e.count(t, `SELECT COUNT(*) FROM schema_migrations`); n != len(files) || n == 0 {
		t.Fatalf("schema_migrations rows = %d, want %d", n, len(files))
	}
}

func TestIngestLifecycle(t *testing.T) {
	e := newEnv(t)
	h, _ := e.enrollHost(t, "client_a", "vm1")
	t0 := e.now

	// 1. New findings.
	e.ingest(t, h, domain.StatusOK, "CVE-A", "CVE-B")
	f := e.findings(t, h.ID)
	if len(f) != 2 || f["CVE-A"].resolved != nil || !f["CVE-A"].firstSeen.Equal(t0) {
		t.Fatalf("new: %+v", f)
	}

	// 2. A still present, B gone -> B resolved, A keeps first_seen.
	e.tick()
	t1 := e.now
	e.ingest(t, h, domain.StatusOK, "CVE-A")
	f = e.findings(t, h.ID)
	if !f["CVE-A"].firstSeen.Equal(t0) || !f["CVE-A"].lastSeen.Equal(t1) || f["CVE-A"].resolved != nil {
		t.Fatalf("still present: %+v", f["CVE-A"])
	}
	if f["CVE-B"].resolved == nil || !f["CVE-B"].resolved.Equal(t1) {
		t.Fatalf("resolved: %+v", f["CVE-B"])
	}

	// 3. B reappears -> reopened, first_seen kept.
	e.tick()
	e.ingest(t, h, domain.StatusOK, "CVE-A", "CVE-B")
	f = e.findings(t, h.ID)
	if f["CVE-B"].resolved != nil || !f["CVE-B"].firstSeen.Equal(t0) {
		t.Fatalf("reappeared: %+v", f["CVE-B"])
	}

	// 4. Error scan -> recorded, nothing resolved.
	e.tick()
	e.ingest(t, h, domain.StatusError)
	f = e.findings(t, h.ID)
	if f["CVE-A"].resolved != nil || f["CVE-B"].resolved != nil {
		t.Fatalf("error scan resolved findings: %+v", f)
	}

	if n := e.count(t, `SELECT COUNT(*) FROM scans WHERE host_id = ?`, h.ID); n != 4 {
		t.Fatalf("scans = %d", n)
	}
	var status string
	var total, high int
	e.db.QueryRow(`SELECT status, total, high FROM scans WHERE host_id = ? ORDER BY id LIMIT 1`, h.ID).Scan(&status, &total, &high)
	if status != "ok" || total != 2 || high != 2 {
		t.Fatalf("first scan row: %s %d %d", status, total, high)
	}
	hosts, _ := e.admin.ListHosts(context.Background(), "client_a")
	if hosts[0].LastScanStatus != domain.StatusError || hosts[0].TrivyVersion != "0.72.0" {
		t.Fatalf("host after error scan: %+v", hosts[0])
	}
}

func TestLargeUpsert(t *testing.T) {
	e := newEnv(t)
	h, _ := e.enrollHost(t, "client_a", "vm1")
	cves := make([]string, 5000)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-%05d", i)
	}
	e.ingest(t, h, domain.StatusOK, cves...)
	e.tick()
	e.ingest(t, h, domain.StatusOK, cves[:4000]...)
	open := e.count(t, `SELECT COUNT(*) FROM findings WHERE host_id = ? AND resolved_at IS NULL`, h.ID)
	all := e.count(t, `SELECT COUNT(*) FROM findings WHERE host_id = ?`, h.ID)
	if open != 4000 || all != 5000 {
		t.Fatalf("open=%d all=%d", open, all)
	}
}

func TestEnrollRevokeReenroll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	enrollTok, err := e.admin.CreateClient(ctx, "client_a")
	if err != nil {
		t.Fatal(err)
	}
	req := domain.EnrollRequest{ClientName: "client_a", EnrollToken: enrollTok, Hostname: "vm1"}
	tok1, err := e.enroll.Run(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	h1, _ := e.agent.Authenticate(ctx, tok1)
	e.ingest(t, h1, domain.StatusOK, "CVE-A")

	if _, err := e.enroll.Run(ctx, req); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second enroll: %v", err)
	}
	if _, err := e.admin.RevokeHost(ctx, "vm1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.agent.Authenticate(ctx, tok1); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("revoked token still works: %v", err)
	}
	tok2, err := e.enroll.Run(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := e.agent.Authenticate(ctx, tok2)
	if err != nil || h2.ID != h1.ID || len(e.findings(t, h2.ID)) != 1 {
		t.Fatalf("re-enroll: h2=%+v err=%v (history must be kept)", h2, err)
	}
}

func TestScanConfigRoundtrip(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	h, _ := e.enrollHost(t, "client_a", "vm1")
	if cfg, err := e.agent.ScanConfig(ctx, h); err != nil || cfg != nil {
		t.Fatalf("default: %s %v", cfg, err)
	}
	want := `{"severity":["CRITICAL"]}`
	if err := e.admin.SetScanConfig(ctx, "client_a", []byte(want)); err != nil {
		t.Fatal(err)
	}
	cfg, _ := e.agent.ScanConfig(ctx, h)
	var got, w any
	json.Unmarshal(cfg, &got)
	json.Unmarshal([]byte(want), &w)
	if fmt.Sprint(got) != fmt.Sprint(w) {
		t.Fatalf("got %s", cfg)
	}
	e.admin.SetScanConfig(ctx, "client_a", nil)
	if cfg, _ := e.agent.ScanConfig(ctx, h); cfg != nil {
		t.Fatalf("cleared: %s", cfg)
	}
}

// TestTenantIsolation drives the real HTTP API: a client A token must not be
// able to write anything for client B.
func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	hostA, tokA := e.enrollHost(t, "client_a", "vm-a")
	hostB, _ := e.enrollHost(t, "client_b", "vm-b")
	app := httpapi.New(e.agent, e.enroll,
		slog.New(slog.NewTextHandler(io.Discard, nil)), httpapi.Options{Limits: httpapi.DefaultLimits()}).App()

	send := func(clientID, hostname string) int {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		json.NewEncoder(zw).Encode(wire.Report{
			ClientID: clientID, Host: wire.Host{Hostname: hostname}, ScannedAt: e.now, Status: "ok",
			Findings: []wire.Finding{{VulnerabilityID: "CVE-X", PkgName: "p", Severity: "HIGH"}},
		})
		zw.Close()
		req := httptest.NewRequest("POST", "/api/v1/report", &buf)
		req.Header.Set("Authorization", "Bearer "+tokA)
		req.Header.Set("Content-Encoding", "gzip")
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := send("client_b", "vm-b"); code != http.StatusForbidden {
		t.Fatalf("A token as client B: %d", code)
	}
	if code := send("client_a", "vm-b"); code != http.StatusForbidden {
		t.Fatalf("A token for B's hostname: %d", code)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM scans WHERE host_id = ?`, hostB.ID); n != 0 {
		t.Fatalf("client B got %d scans", n)
	}
	if code := send("client_a", "vm-a"); code != http.StatusNoContent {
		t.Fatalf("own report: %d", code)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM findings WHERE host_id = ?`, hostA.ID); n != 1 {
		t.Fatalf("client A findings = %d", n)
	}
}
