package test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/model"
)

const (
	origin   = "http://central.test"
	password = "correct horse battery"
)

// ClearAll empties every table. DELETE (not TRUNCATE) keeps ids growing, so
// per-host rate limiter keys never repeat across tests.
func ClearAll(t *testing.T) {
	t.Helper()
	for _, table := range []string{"mcp_tokens", "admin_sessions", "admin_users", "findings", "scans", "hosts", "enroll_tokens", "clients"} {
		require.NoError(t, db.Exec("DELETE FROM "+table).Error)
	}
	clear(enrollTokens)
}

func count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, db.Raw(query, args...).Scan(&n).Error)
	return n
}

// send runs req through a; the body is read and closed.
func send(t *testing.T, a *fiber.App, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := a.Test(req, fiber.TestConfig{Timeout: 0})
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

// agentReq builds an agent API request; gz compresses the body like the agent does.
func agentReq(method, path, token string, body []byte, gz bool) *http.Request {
	var r io.Reader = bytes.NewReader(body)
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		r = &buf
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func agentStatus(t *testing.T, method, path, token string, body []byte, gz bool) int {
	t.Helper()
	resp, _ := send(t, app, agentReq(method, path, token, body, gz))
	return resp.StatusCode
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// newClient creates a client and returns its enroll token.
func newClient(t *testing.T, name string) string {
	t.Helper()
	_, err := uc.Client.Create(context.Background(), &model.CreateClientRequest{Name: name})
	require.NoError(t, err)
	return issueToken(t, name)
}

func issueToken(t *testing.T, name string) string {
	t.Helper()
	res, err := uc.Client.IssueEnrollToken(context.Background(), &model.IssueEnrollTokenRequest{Name: name})
	require.NoError(t, err)
	return res.EnrollToken
}

func enrollStatus(t *testing.T, client, enrollToken, hostname string) (int, string) {
	t.Helper()
	body := mustJSON(wire.EnrollRequest{ClientID: client, EnrollToken: enrollToken, Host: wire.Host{Hostname: hostname}})
	resp, b := send(t, app, agentReq("POST", "/api/v1/enroll", "", body, false))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	var out wire.EnrollResponse
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // what the agent does
	require.NoError(t, dec.Decode(&out))
	return resp.StatusCode, out.HostToken
}

type host struct {
	ID       int64
	Client   string
	Hostname string
	Token    string
}

// enrollTokens remembers each client's enroll token (shown once, reusable).
var enrollTokens = map[string]string{}

// enrollHost creates the client when needed and enrolls hostname.
func enrollHost(t *testing.T, client, hostname string) host {
	t.Helper()
	if _, ok := enrollTokens[client]; !ok {
		enrollTokens[client] = newClient(t, client)
	}
	code, token := enrollStatus(t, client, issueToken(t, client), hostname)
	require.Equal(t, http.StatusOK, code)
	var id int64
	require.NoError(t, db.Raw("SELECT id FROM hosts WHERE hostname = ?", hostname).Scan(&id).Error)
	return host{ID: id, Client: client, Hostname: hostname, Token: token}
}

func vuln(cve, severity, pkg string) wire.Finding {
	return wire.Finding{Target: "vm (ubuntu 24.04)", Type: "ubuntu", VulnerabilityID: cve, PkgName: pkg,
		InstalledVersion: "1.0", FixedVersion: "1.1", Severity: severity, Title: cve + " in " + pkg}
}

func report(h host, status string, findings ...wire.Finding) wire.Report {
	r := wire.Report{
		ClientID: h.Client, TrivyVersion: "0.72.0", ScannedAt: time.Now(), ScanDurationSeconds: 1.5, Status: status,
		Host: wire.Host{Hostname: h.Hostname, OSFamily: "ubuntu", OSName: "Ubuntu", OSVersion: "24.04", AgentVersion: "0.2.0"},
	}
	if findings == nil {
		findings = []wire.Finding{}
	}
	r.Findings = findings
	if status == "error" {
		r.Error = "trivy failed"
		r.Findings = nil
	}
	return r
}

// ingest sends a report and requires 204.
func ingest(t *testing.T, h host, status string, findings ...wire.Finding) {
	t.Helper()
	code := agentStatus(t, "POST", "/api/v1/report", h.Token, mustJSON(report(h, status, findings...)), true)
	require.Equal(t, http.StatusNoContent, code)
}

func cves(ids ...string) []wire.Finding {
	out := make([]wire.Finding, len(ids))
	for i, id := range ids {
		out[i] = vuln(id, "HIGH", "openssl")
	}
	return out
}

type findingRow struct {
	CVE        string
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt *time.Time
}

func findings(t *testing.T, hostID int64) map[string]findingRow {
	t.Helper()
	var rows []findingRow
	require.NoError(t, db.Raw("SELECT cve, first_seen, last_seen, resolved_at FROM findings WHERE host_id = ?", hostID).Scan(&rows).Error)
	out := map[string]findingRow{}
	for _, r := range rows {
		out[r.CVE] = r
	}
	return out
}

// --- admin API ---

func newAdmin(t *testing.T, username string) {
	t.Helper()
	require.NoError(t, uc.AdminUser.Create(context.Background(), &model.CreateAdminRequest{Username: username, Password: password}))
}

// adminReq builds a same-origin admin request; cookie "" = logged out.
func adminReq(method, path, body, cookie string) *http.Request {
	req := httptest.NewRequest(method, origin+"/api/admin/v1"+path, strings.NewReader(body))
	req.Header.Set("Origin", origin)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "vuln_session", Value: cookie})
	}
	return req
}

func adminDo(t *testing.T, method, path, body, cookie string) (int, []byte) {
	t.Helper()
	resp, b := send(t, app, adminReq(method, path, body, cookie))
	return resp.StatusCode, b
}

// login signs username in and returns the session cookie value.
func login(t *testing.T, username, pw string) string {
	t.Helper()
	resp, _ := send(t, app, adminReq("POST", "/login", string(mustJSON(map[string]string{"username": username, "password": pw})), ""))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	for _, c := range resp.Cookies() {
		if c.Name == "vuln_session" {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// adminSession creates admin "ops" and logs in.
func adminSession(t *testing.T) string {
	t.Helper()
	newAdmin(t, "ops")
	return login(t, "ops", password)
}

// getData decodes a WebResponse's data from an admin GET that must succeed.
func getData[T any](t *testing.T, cookie, path string) (T, *model.PageMetadata) {
	t.Helper()
	code, b := adminDo(t, "GET", path, "", cookie)
	require.Equal(t, http.StatusOK, code, string(b))
	var res model.WebResponse[T]
	require.NoError(t, json.Unmarshal(b, &res))
	return res.Data, res.Paging
}
