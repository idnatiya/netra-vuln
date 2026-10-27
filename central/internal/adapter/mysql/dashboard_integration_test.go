package mysql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netra-vuln/central/internal/domain"
	"netra-vuln/central/internal/usecase"
)

func (e *env) dashboard() *usecase.Dashboard {
	clock := func() time.Time { return e.now }
	return &usecase.Dashboard{Queries: e.store, Store: e.store, Admin: e.admin, Now: clock}
}

func (e *env) ingestFindings(t *testing.T, h domain.Host, fs ...domain.Finding) {
	t.Helper()
	r := domain.Report{ClientName: h.ClientName, Hostname: h.Hostname, Status: domain.StatusOK,
		ScannedAt: e.now, TrivyVersion: "0.72.0", Findings: fs,
		Meta: domain.HostMeta{OSName: "Ubuntu", OSVersion: "24.04", AgentVersion: "1.0.0", AutoUpdateEnabled: true}}
	if err := e.agent.Ingest(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
}

func sev(cve, severity, pkg string) domain.Finding {
	f := finding(cve)
	f.Severity, f.Pkg = severity, pkg
	return f
}

func TestDashboardQueries(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	d := e.dashboard()
	a, _ := e.enrollHost(t, "client_a", "web-1")
	b, _ := e.enrollHost(t, "client_b", "db-1")
	t0 := e.now

	e.ingestFindings(t, a, sev("CVE-1", "CRITICAL", "openssl"), sev("CVE-2", "HIGH", "libc6"), sev("CVE-3", "HIGH", "zlib"))
	e.ingestFindings(t, b, sev("CVE-1", "CRITICAL", "openssl"), sev("CVE-4", "HIGH", "curl"))
	e.agent.Heartbeat(ctx, a, a.ClientName, a.Hostname, domain.HostMeta{AutoUpdateEnabled: true})

	// Triage: accepted findings leave the open counts but keep their verdict across re-scans.
	page, err := d.Findings(ctx, domain.FindingFilter{Client: "client_a", Query: "zlib"})
	if err != nil || page.Total != 1 {
		t.Fatalf("search: %+v %v", page, err)
	}
	zlibID := page.Items[0].ID
	if err := d.TriageFinding(ctx, zlibID, domain.TriageAccepted, "vendor patch pending"); err != nil {
		t.Fatal(err)
	}
	e.tick()
	e.ingestFindings(t, a, sev("CVE-1", "CRITICAL", "openssl"), sev("CVE-2", "HIGH", "libc6"), sev("CVE-3", "HIGH", "zlib"))
	page, _ = d.Findings(ctx, domain.FindingFilter{Status: domain.TriageAccepted})
	if page.Total != 1 || page.Items[0].ID != zlibID || page.Items[0].Note != "vendor patch pending" {
		t.Fatalf("triage after re-scan: %+v", page)
	}

	ov, err := d.Overview(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	want := domain.Totals{Clients: 2, Hosts: 2, OpenCritical: 2, OpenHigh: 2, Accepted: 1, StaleHosts: 1}
	if ov.Totals != want {
		t.Fatalf("totals = %+v, want %+v", ov.Totals, want)
	}
	hosts, _ := d.Hosts(ctx, "")
	byName := map[string]domain.HostRow{}
	for _, h := range hosts {
		byName[h.Hostname] = h
	}
	if h := byName["web-1"]; h.OpenCritical != 1 || h.OpenHigh != 1 || h.Accepted != 1 || h.StaleScan || h.StaleHeartbeat {
		t.Fatalf("web-1 = %+v", h)
	}
	if h := byName["db-1"]; !h.StaleHeartbeat || h.StaleScan { // scanned, never sent a heartbeat
		t.Fatalf("db-1 = %+v", h)
	}

	// Filters, ordering, and paging.
	page, _ = d.Findings(ctx, domain.FindingFilter{Severity: "CRITICAL"})
	if page.Total != 2 {
		t.Fatalf("critical total = %d", page.Total)
	}
	page, _ = d.Findings(ctx, domain.FindingFilter{PageSize: 2, Page: 2})
	if page.Total != 5 || len(page.Items) != 2 {
		t.Fatalf("paging: total=%d items=%d", page.Total, len(page.Items))
	}
	page, _ = d.Findings(ctx, domain.FindingFilter{Query: "100%_"}) // wildcards are escaped
	if page.Total != 0 {
		t.Fatalf("escaped search matched %d", page.Total)
	}

	// Trend: last scan per host per day, summed.
	trend, err := d.Trend(ctx, "", 0, 7)
	if err != nil || len(trend) != 1 {
		t.Fatalf("trend: %+v %v", trend, err)
	}
	if p := trend[0]; p.Critical != 2 || p.High != 3 || !p.Day.Equal(t0.Truncate(24*time.Hour)) {
		t.Fatalf("trend point = %+v", p)
	}

	cves, _ := d.OldestCVEs(ctx, "", 10)
	if len(cves) != 3 || cves[0].CVE != "CVE-1" || cves[0].Hosts != 2 {
		t.Fatalf("oldest = %+v", cves)
	}

	dist, _ := d.Distribution(ctx)
	if len(dist.OS) != 1 || dist.OS[0] != (domain.Count{Key: "Ubuntu 24.04", N: 2}) {
		t.Fatalf("distribution = %+v", dist)
	}

	// Revoked hosts drop out of findings and totals.
	if _, err := d.RevokeHost(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RevokeHost(ctx, b.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second revoke: %v", err)
	}
	page, _ = d.Findings(ctx, domain.FindingFilter{})
	if page.Total != 3 { // web-1 only: CVE-1, CVE-2 open + CVE-3 accepted (no status filter)
		t.Fatalf("after revoke total = %d", page.Total)
	}
	for _, it := range page.Items {
		if it.Hostname == "db-1" {
			t.Fatal("revoked host still listed")
		}
	}
	if err := d.TriageFinding(ctx, 999999, domain.TriageOpen, ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("triage missing: %v", err)
	}
}

func TestAdminSessionsInDB(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	auth := &usecase.AdminAuth{Store: e.store, Now: func() time.Time { return e.now }, Cost: bcrypt.MinCost}
	if err := auth.CreateAdmin(ctx, "ops", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := auth.CreateAdmin(ctx, "ops", "correct horse battery"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate admin: %v", err)
	}
	tok, _, err := auth.Login(ctx, "ops", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if s, err := auth.Session(ctx, tok); err != nil || s.Username != "ops" {
		t.Fatalf("session: %+v %v", s, err)
	}
	if n := e.count(t, `SELECT COUNT(*) FROM admin_sessions WHERE token_hash = ?`, []byte(tok)); n != 0 {
		t.Fatal("session token stored in plaintext")
	}
	e.now = e.now.Add(usecase.DefaultSessionTTL + time.Minute)
	if _, err := auth.Session(ctx, tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expired: %v", err)
	}
	e.db.Exec(`UPDATE admin_users SET disabled_at = ? WHERE username = 'ops'`, e.now)
	if _, _, err := auth.Login(ctx, "ops", "correct horse battery"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("disabled login: %v", err)
	}
}
