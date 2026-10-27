package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/domain"
	"netra-vuln/internal/wire"
)

type fakeAgent struct {
	host      domain.Host
	ingested  []domain.Report
	hbClient  string
	scanCfg   []byte
	ingestErr error
}

func (f *fakeAgent) Authenticate(_ context.Context, token string) (domain.Host, error) {
	if token != "good" {
		return domain.Host{}, domain.ErrUnauthorized
	}
	return f.host, nil
}
func (f *fakeAgent) Heartbeat(_ context.Context, _ domain.Host, clientName, _ string, _ domain.HostMeta) error {
	f.hbClient = clientName
	if clientName != f.host.ClientName {
		return domain.ErrForbidden
	}
	return nil
}
func (f *fakeAgent) Ingest(_ context.Context, _ domain.Host, r domain.Report) error {
	f.ingested = append(f.ingested, r)
	return f.ingestErr
}
func (f *fakeAgent) ScanConfig(context.Context, domain.Host) ([]byte, error) { return f.scanCfg, nil }
func (f *fakeAgent) Ping(context.Context) error                              { return nil }

type fakeEnroller struct{ err error }

func (f fakeEnroller) Run(context.Context, domain.EnrollRequest) (string, error) {
	return "new-host-token", f.err
}

type testServer struct {
	URL string // path prefix only; requests go through app.Test, not a listener
	app *fiber.App
}

func newTestServer(t *testing.T, limits Limits) (*testServer, *fakeAgent) {
	t.Helper()
	a := &fakeAgent{host: domain.Host{ID: 1, ClientName: "client_a", Hostname: "vm1"}}
	srv := New(a, fakeEnroller{}, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Limits: limits})
	return &testServer{URL: "http://central.test", app: srv.App()}, a
}

func (s *testServer) send(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := s.app.Test(req, fiber.TestConfig{Timeout: 0}) // no timeout
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (s *testServer) do(t *testing.T, method, url, token string, body []byte, gz bool) *http.Response {
	t.Helper()
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		body = buf.Bytes()
	}
	req := httptest.NewRequest(method, url, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	return s.send(t, req)
}

func reportJSON(t *testing.T, extra string) []byte {
	t.Helper()
	r := wire.Report{
		ClientID: "client_a", Host: wire.Host{Hostname: "vm1", UnattendedUpgradesEnabled: true},
		ScannedAt: time.Now(), ScanDurationSeconds: 1.5, Status: "ok",
		Findings: []wire.Finding{{VulnerabilityID: "CVE-1", PkgName: "openssl", Severity: "HIGH"}},
	}
	b, _ := json.Marshal(r)
	if extra != "" { // inject an unknown field from a hypothetical newer agent
		b = append(b[:len(b)-1], []byte(`,`+extra+`}`)...)
	}
	return b
}

func TestReport(t *testing.T) {
	srv, a := newTestServer(t, DefaultLimits())
	resp := srv.do(t, "POST", srv.URL+"/api/v1/report", "good", reportJSON(t, `"new_field":{"x":1}`), true)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := a.ingested[0]
	if got.ClientName != "client_a" || got.Hostname != "vm1" || !got.Meta.AutoUpdateEnabled ||
		got.Duration != 1500*time.Millisecond || got.Findings[0].CVE != "CVE-1" {
		t.Fatalf("mapped report = %+v", got)
	}
}

func TestStatusCodes(t *testing.T) {
	srv, a := newTestServer(t, DefaultLimits())
	cases := []struct {
		name   string
		token  string
		body   []byte
		gz     bool
		setErr error
		want   int
	}{
		{"no token", "", reportJSON(t, ""), true, nil, 401},
		{"bad token", "nope", reportJSON(t, ""), true, nil, 401},
		{"broken json", "good", []byte("{"), true, nil, 400},
		{"tenant", "good", reportJSON(t, ""), true, domain.ErrForbidden, 403},
		{"invalid", "good", reportJSON(t, ""), true, domain.ErrInvalid, 400},
		{"internal", "good", reportJSON(t, ""), true, fmt.Errorf("db down"), 500},
	}
	for _, c := range cases {
		a.ingestErr = c.setErr
		if got := srv.do(t, "POST", srv.URL+"/api/v1/report", c.token, c.body, c.gz).StatusCode; got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}

	for enc, want := range map[string]int{
		"gzip": 400, // claims gzip but is not
		"br":   415,
	} {
		req := httptest.NewRequest("POST", srv.URL+"/api/v1/report", strings.NewReader("not compressed"))
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Encoding", enc)
		if got := srv.send(t, req).StatusCode; got != want {
			t.Errorf("Content-Encoding %s: status %d, want %d", enc, got, want)
		}
	}
}

func TestReportTooLarge(t *testing.T) {
	srv, a := newTestServer(t, DefaultLimits())
	// ~21 MB of zeros compresses to ~20 KB: the decompressed limit must catch it.
	huge := append([]byte(`{"title":"`), bytes.Repeat([]byte("0"), maxReportBytes+1<<20)...)
	if got := srv.do(t, "POST", srv.URL+"/api/v1/report", "good", huge, true).StatusCode; got != 413 {
		t.Fatalf("gzip bomb: status %d", got)
	}

	// A raw body over BodyLimit is cut off by fasthttp before routing: the client
	// sees 413 or a connection reset (the agent then spools and retries, bounded by
	// its 5-file spool). Either way it must never reach Ingest.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	t.Cleanup(func() { srv.app.Shutdown() })
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/api/v1/report", bytes.NewReader(huge))
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 413 {
			t.Fatalf("raw: status %d", resp.StatusCode)
		}
	}
	if len(a.ingested) != 0 {
		t.Fatal("oversize report was ingested")
	}
}

func TestEnrollResponseMatchesAgentContract(t *testing.T) {
	srv, _ := newTestServer(t, DefaultLimits())
	body, _ := json.Marshal(wire.EnrollRequest{ClientID: "client_a", EnrollToken: "t", Host: wire.Host{Hostname: "vm1"}})
	resp := srv.do(t, "POST", srv.URL+"/api/v1/enroll", "", body, false)
	var out wire.EnrollResponse
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields() // what the agent does
	if err := dec.Decode(&out); err != nil || resp.StatusCode != 200 || out.HostToken != "new-host-token" {
		t.Fatalf("status=%d out=%+v err=%v", resp.StatusCode, out, err)
	}
}

func TestConfigMatchesAgentContract(t *testing.T) {
	srv, a := newTestServer(t, DefaultLimits())
	for _, stored := range []string{"", `{"severity":["CRITICAL"],"timeout":"45m"}`} {
		a.scanCfg = []byte(stored)
		resp := srv.do(t, "GET", srv.URL+"/api/v1/config", "good", nil, false)
		var cfg wire.ScanConfig
		dec := json.NewDecoder(resp.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil || resp.StatusCode != 200 {
			t.Fatalf("stored %q: status=%d err=%v", stored, resp.StatusCode, err)
		}
		if _, err := cfg.Resolve(); err != nil {
			t.Fatalf("stored %q: agent would reject: %v", stored, err)
		}
	}
	// A corrupt stored config must not leak unknown fields to agents.
	a.scanCfg = []byte(`{"command":"rm -rf /"}`)
	if got := srv.do(t, "GET", srv.URL+"/api/v1/config", "good", nil, false).StatusCode; got != 500 {
		t.Fatalf("corrupt config: status %d", got)
	}
}

func TestHeartbeat(t *testing.T) {
	srv, _ := newTestServer(t, DefaultLimits())
	ok, _ := json.Marshal(wire.Heartbeat{ClientID: "client_a", Host: wire.Host{Hostname: "vm1"}})
	if got := srv.do(t, "POST", srv.URL+"/api/v1/heartbeat", "good", ok, false).StatusCode; got != 204 {
		t.Fatalf("status %d", got)
	}
	other, _ := json.Marshal(wire.Heartbeat{ClientID: "client_b", Host: wire.Host{Hostname: "vm1"}})
	if got := srv.do(t, "POST", srv.URL+"/api/v1/heartbeat", "good", other, false).StatusCode; got != 403 {
		t.Fatalf("other client: status %d", got)
	}
}

func TestRateLimits(t *testing.T) {
	limits := Limits{Window: time.Hour, PerHostMax: 2, EnrollMax: 1, AuthMax: 1000, LoginMax: 10}
	srv, _ := newTestServer(t, limits)
	codes := []int{}
	for range 3 {
		codes = append(codes, srv.do(t, "GET", srv.URL+"/api/v1/config", "good", nil, false).StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("per-host codes = %v", codes)
	}
	body, _ := json.Marshal(wire.EnrollRequest{ClientID: "client_a", EnrollToken: "t", Host: wire.Host{Hostname: "vm1"}})
	srv.do(t, "POST", srv.URL+"/api/v1/enroll", "", body, false)
	if got := srv.do(t, "POST", srv.URL+"/api/v1/enroll", "", body, false).StatusCode; got != 429 {
		t.Fatalf("enroll: status %d", got)
	}
}
