package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/delivery/http/middleware"
	"netra-vuln/core/internal/delivery/http/route"
)

func TestHealthz(t *testing.T) {
	resp, body := send(t, app, httptest.NewRequest("GET", "/healthz", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok\n", string(body))
}

func TestEnroll(t *testing.T) {
	ClearAll(t)
	tok := newClient(t, "client_a")

	code, hostTok := enrollStatus(t, "client_a", tok, "vm1")
	require.Equal(t, http.StatusOK, code)
	assert.Len(t, hostTok, 64)
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM hosts WHERE host_token_hash = UNHEX(SHA2(?, 256))", hostTok),
		"token must be stored as its SHA-256 hash")

	code, _ = enrollStatus(t, "client_a", tok, "vm1")
	assert.Equal(t, http.StatusConflict, code, "active host")

	for name, c := range map[string][3]string{
		"bad token":      {"client_a", "nope", "vm2"},
		"unknown client": {"client_x", tok, "vm2"},
	} {
		code, _ := enrollStatus(t, c[0], c[1], c[2])
		assert.Equal(t, http.StatusUnauthorized, code, name)
	}
	code, _ = enrollStatus(t, "client_a", tok, "")
	assert.Equal(t, http.StatusBadRequest, code, "empty hostname")
}

func TestEnrollRevokeReenroll(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	ingest(t, h, "ok", cves("CVE-A")...)

	cookie := adminSession(t)
	code, _ := adminDo(t, "POST", fmt.Sprintf("/hosts/%d/revoke", h.ID), "", cookie)
	require.Equal(t, http.StatusNoContent, code)
	code, _ = adminDo(t, "POST", fmt.Sprintf("/hosts/%d/revoke", h.ID), "", cookie)
	assert.Equal(t, http.StatusConflict, code, "second revoke")
	assert.Equal(t, http.StatusUnauthorized, agentStatus(t, "GET", "/api/v1/config", h.Token, nil, false), "revoked token")

	code, tok2 := enrollStatus(t, "client_a", enrollTokens["client_a"], "vm1")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, http.StatusOK, agentStatus(t, "GET", "/api/v1/config", tok2, nil, false))
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM hosts"), "re-enroll reactivates the same host")
	assert.Len(t, findings(t, h.ID), 1, "history must be kept")
}

func TestReport(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	r := report(h, "ok", vuln("CVE-1", "HIGH", "openssl"))
	r.Host.UnattendedUpgradesEnabled = true
	b := mustJSON(r)
	b = append(b[:len(b)-1], []byte(`,"new_field":{"x":1}}`)...) // a newer agent's unknown field
	require.Equal(t, http.StatusNoContent, agentStatus(t, "POST", "/api/v1/report", h.Token, b, true))

	var row struct {
		AutoUpdateEnabled bool
		TrivyVersion      string
		LastScanStatus    string
	}
	db.Raw("SELECT auto_update_enabled, trivy_version, last_scan_status FROM hosts WHERE id = ?", h.ID).Scan(&row)
	assert.True(t, row.AutoUpdateEnabled)
	assert.Equal(t, "0.72.0", row.TrivyVersion)
	assert.Equal(t, "ok", row.LastScanStatus)
	assert.Equal(t, 1.5, func() float64 {
		var d float64
		db.Raw("SELECT duration_seconds FROM scans WHERE host_id = ?", h.ID).Scan(&d)
		return d
	}())
}

func TestReportStatusCodes(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	other := enrollHost(t, "client_b", "vm-b")
	good := mustJSON(report(h, "ok", cves("CVE-1")...))
	bad := report(h, "ok", cves("CVE-1")...)
	bad.Status = "weird"
	noCVE := report(h, "ok", wire.Finding{PkgName: "p", Severity: "HIGH"})

	cases := []struct {
		name  string
		token string
		body  []byte
		want  int
	}{
		{"no token", "", good, 401},
		{"bad token", "nope", good, 401},
		{"broken json", h.Token, []byte("{"), 400},
		{"other client's token", other.Token, good, 403},
		{"invalid status", h.Token, mustJSON(bad), 400},
		{"empty cve", h.Token, mustJSON(noCVE), 400},
		{"ok", h.Token, good, 204},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, agentStatus(t, "POST", "/api/v1/report", c.token, c.body, true), c.name)
	}

	for enc, want := range map[string]int{
		"gzip": 400, // claims gzip but is not
		"br":   415,
	} {
		req := httptest.NewRequest("POST", "/api/v1/report", strings.NewReader("not compressed"))
		req.Header.Set("Authorization", "Bearer "+h.Token)
		req.Header.Set("Content-Encoding", enc)
		resp, _ := send(t, app, req)
		assert.Equal(t, want, resp.StatusCode, "Content-Encoding %s", enc)
	}
}

func TestReportTooLarge(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	// ~21 MB of zeros compresses to ~20 KB: the decompressed limit must catch it.
	huge := append([]byte(`{"title":"`), bytes.Repeat([]byte("0"), middleware.MaxReportBytes+1<<20)...)
	assert.Equal(t, 413, agentStatus(t, "POST", "/api/v1/report", h.Token, huge, true), "gzip bomb")

	// A raw body over BodyLimit is cut off by fasthttp before routing: the client
	// sees 413 or a connection reset (the agent then spools and retries). Either
	// way it must never be ingested.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	defer ln.Close()
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/api/v1/report", bytes.NewReader(huge))
	req.Header.Set("Authorization", "Bearer "+h.Token)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		assert.Equal(t, 413, resp.StatusCode, "raw")
	}
	assert.Zero(t, count(t, "SELECT COUNT(*) FROM scans"), "oversize report was ingested")
}

func TestHeartbeat(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	ok := mustJSON(wire.Heartbeat{ClientID: "client_a", Host: wire.Host{Hostname: "vm1", RebootRequired: true}})
	require.Equal(t, 204, agentStatus(t, "POST", "/api/v1/heartbeat", h.Token, ok, false))
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM hosts WHERE id = ? AND reboot_required AND last_heartbeat_at IS NOT NULL", h.ID))

	other := mustJSON(wire.Heartbeat{ClientID: "client_b", Host: wire.Host{Hostname: "vm1"}})
	assert.Equal(t, 403, agentStatus(t, "POST", "/api/v1/heartbeat", h.Token, other, false), "other client")
	big := mustJSON(wire.Heartbeat{ClientID: "client_a", Host: wire.Host{Hostname: strings.Repeat("a", middleware.MaxSmallBytes)}})
	assert.Equal(t, 413, agentStatus(t, "POST", "/api/v1/heartbeat", h.Token, big, false), "over the small body limit")
}

func TestConfigMatchesAgentContract(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	cookie := adminSession(t)
	for _, stored := range []string{"", `{"severity":["CRITICAL"],"timeout":"45m"}`} {
		if stored != "" {
			code, _ := adminDo(t, "PUT", "/clients/client_a/scan-config", stored, cookie)
			require.Equal(t, 200, code)
		}
		resp, b := send(t, app, agentReq("GET", "/api/v1/config", h.Token, nil, false))
		require.Equal(t, 200, resp.StatusCode)
		var cfg wire.ScanConfig
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields() // what the agent does
		require.NoError(t, dec.Decode(&cfg), "stored %q", stored)
		_, err := cfg.Resolve()
		require.NoError(t, err, "stored %q: agent would reject", stored)
		if stored != "" {
			assert.Equal(t, []string{"CRITICAL"}, *cfg.Severity)
		}
	}
	code, _ := adminDo(t, "DELETE", "/clients/client_a/scan-config", "", cookie)
	require.Equal(t, 204, code)
	assert.Zero(t, count(t, "SELECT COUNT(*) FROM clients WHERE scan_config IS NOT NULL"))

	// A corrupt stored config must not leak unknown fields to agents.
	require.NoError(t, db.Exec(`UPDATE clients SET scan_config = '{"command":"rm -rf /"}'`).Error)
	assert.Equal(t, 500, agentStatus(t, "GET", "/api/v1/config", h.Token, nil, false), "corrupt config")
}

func TestTenantIsolation(t *testing.T) {
	ClearAll(t)
	a := enrollHost(t, "client_a", "vm-a")
	b := enrollHost(t, "client_b", "vm-b")
	asB := a
	asB.Client, asB.Hostname = "client_b", "vm-b"
	assert.Equal(t, 403, agentStatus(t, "POST", "/api/v1/report", a.Token, mustJSON(report(asB, "ok", cves("CVE-X")...)), true))
	asB.Client = "client_a"
	assert.Equal(t, 403, agentStatus(t, "POST", "/api/v1/report", a.Token, mustJSON(report(asB, "ok", cves("CVE-X")...)), true))
	assert.Zero(t, count(t, "SELECT COUNT(*) FROM scans WHERE host_id = ?", b.ID))
	ingest(t, a, "ok", cves("CVE-X")...)
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM findings WHERE host_id = ?", a.ID))
}

func TestRateLimits(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	limited := newApp(route.Limits{Window: time.Hour, PerHostMax: 2, EnrollMax: 1, AuthMax: 1000, LoginMax: 2})
	defer func() { app = newApp(testLimits) }()

	var codes []int
	for range 3 {
		resp, _ := send(t, limited, agentReq("GET", "/api/v1/config", h.Token, nil, false))
		codes = append(codes, resp.StatusCode)
	}
	assert.Equal(t, []int{200, 200, 429}, codes, "per host")

	body := mustJSON(wire.EnrollRequest{ClientID: "client_a", EnrollToken: "x", Host: wire.Host{Hostname: "vm2"}})
	send(t, limited, agentReq("POST", "/api/v1/enroll", "", body, false))
	resp, _ := send(t, limited, agentReq("POST", "/api/v1/enroll", "", body, false))
	assert.Equal(t, 429, resp.StatusCode, "enroll")

	var last int
	for range 3 {
		resp, _ := send(t, limited, adminReq("POST", "/login", `{"username":"ops","password":"x"}`, ""))
		last = resp.StatusCode
	}
	assert.Equal(t, 429, last, "login")
}
