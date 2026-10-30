package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/domain"
)

type fakeAuth struct{}

func (fakeAuth) Login(_ context.Context, u, p string, _ domain.SessionMeta) (string, domain.Session, error) {
	if u != "ops" || p != "correct horse battery" {
		return "", domain.Session{}, domain.ErrUnauthorized
	}
	return "sess-token", domain.Session{Username: "ops", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (fakeAuth) Session(_ context.Context, tok string) (domain.Session, error) {
	if tok != "sess-token" {
		return domain.Session{}, domain.ErrUnauthorized
	}
	return domain.Session{ID: 1, Username: "ops"}, nil
}
func (fakeAuth) Logout(context.Context, string) error { return nil }
func (fakeAuth) ChangePassword(_ context.Context, _ domain.Session, cur, next string) (int, error) {
	if cur != "correct horse battery" {
		return 0, domain.ErrInvalid
	}
	return 2, nil
}
func (fakeAuth) ListSessions(_ context.Context, s domain.Session) ([]domain.Session, error) {
	return []domain.Session{{ID: 1, IP: "100.64.0.7", Current: true}, {ID: 2}}, nil
}
func (fakeAuth) RevokeSession(_ context.Context, s domain.Session, id int64) error {
	if id == s.ID {
		return domain.ErrConflict
	}
	return nil
}
func (fakeAuth) RevokeOtherSessions(context.Context, domain.Session) (int, error) { return 1, nil }

type fakeDash struct {
	Dashboard // unimplemented methods panic, flagging unexpected calls
	filter    domain.FindingFilter
	triaged   domain.TriageStatus
	scanCfg   []byte
}

func (f *fakeDash) Findings(_ context.Context, flt domain.FindingFilter) (domain.Page[domain.FindingRow], error) {
	f.filter = flt
	return domain.Page[domain.FindingRow]{Items: []domain.FindingRow{{ID: 7, Status: domain.TriageOpen}}, Total: 1}, nil
}
func (f *fakeDash) TriageFinding(_ context.Context, _ int64, s domain.TriageStatus, _ string) error {
	if !s.Valid() {
		return domain.ErrInvalid
	}
	f.triaged = s
	return nil
}
func (f *fakeDash) SetScanConfig(_ context.Context, _ string, cfg []byte) error {
	f.scanCfg = cfg
	return nil
}
func (f *fakeDash) Clients(context.Context) ([]domain.ClientRow, error) {
	return []domain.ClientRow{{Client: domain.Client{Name: "a"}}, {Client: domain.Client{Name: "b", ScanConfig: []byte(`{"timeout":"45m"}`)}}}, nil
}

const origin = "http://central.test"

func newAdminServer(t *testing.T, limits Limits) (*fiber.App, *fakeDash) {
	t.Helper()
	d := &fakeDash{}
	s := New(&fakeAgent{}, fakeEnroller{}, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Limits: limits})
	s.MountAdmin(fakeAuth{}, d)
	return s.App(), d
}

// adminReq builds a same-origin request; cookie "" = logged out.
func adminReq(method, path, body, cookie string) *http.Request {
	req := httptest.NewRequest(method, origin+adminPrefix+path, strings.NewReader(body))
	req.Header.Set("Origin", origin)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	return req
}

func send(t *testing.T, app *fiber.App, req *http.Request) *http.Response {
	t.Helper()
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestLoginSetsHardenedCookie(t *testing.T) {
	app, _ := newAdminServer(t, DefaultLimits())
	resp := send(t, app, adminReq("POST", "/login", `{"username":"ops","password":"correct horse battery"}`, ""))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c := resp.Cookies()[0]
	if c.Name != sessionCookie || c.Value != "sess-token" || !c.HttpOnly || !c.Secure ||
		c.SameSite != http.SameSiteStrictMode || c.Path != "/api/admin" {
		t.Fatalf("cookie = %+v", c)
	}
	if got := send(t, app, adminReq("POST", "/login", `{"username":"ops","password":"nope"}`, "")).StatusCode; got != 401 {
		t.Fatalf("bad password: %d", got)
	}
}

func TestAdminRequiresSession(t *testing.T) {
	app, _ := newAdminServer(t, DefaultLimits())
	for _, path := range []string{"/me", "/overview", "/findings", "/hosts", "/clients", "/trend", "/distribution"} {
		if got := send(t, app, adminReq("GET", path, "", "")).StatusCode; got != 401 {
			t.Errorf("%s without cookie: %d", path, got)
		}
		if got := send(t, app, adminReq("GET", path, "", "forged")).StatusCode; got != 401 {
			t.Errorf("%s with forged cookie: %d", path, got)
		}
	}
	if got := send(t, app, adminReq("GET", "/me", "", "sess-token")).StatusCode; got != 200 {
		t.Fatalf("/me with session: %d", got)
	}
}

func TestAdminRejectsCrossOrigin(t *testing.T) {
	app, d := newAdminServer(t, DefaultLimits())
	for _, o := range []string{"", "https://evil.example", "null"} {
		req := adminReq("PATCH", "/findings/7", `{"status":"accepted"}`, "sess-token")
		if o == "" {
			req.Header.Del("Origin")
		} else {
			req.Header.Set("Origin", o)
		}
		if got := send(t, app, req).StatusCode; got != 403 {
			t.Errorf("origin %q: %d", o, got)
		}
	}
	if d.triaged != "" {
		t.Fatal("cross-origin request reached the handler")
	}
	if got := send(t, app, adminReq("PATCH", "/findings/7", `{"status":"accepted"}`, "sess-token")).StatusCode; got != 204 {
		t.Fatalf("same origin: %d", got)
	}
	if d.triaged != domain.TriageAccepted {
		t.Fatalf("triaged = %q", d.triaged)
	}
}

func TestAccountRoutes(t *testing.T) {
	app, _ := newAdminServer(t, DefaultLimits())
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/me/password", `{"current_password":"correct horse battery","new_password":"brand new passphrase"}`, 200},
		{"POST", "/me/password", `{"current_password":"nope","new_password":"brand new passphrase"}`, 400},
		{"GET", "/me/sessions", "", 200},
		{"DELETE", "/me/sessions/2", "", 204},
		{"DELETE", "/me/sessions/1", "", 409},
		{"DELETE", "/me/sessions/x", "", 400},
		{"DELETE", "/me/sessions", "", 200},
	}
	for _, c := range cases {
		if got := send(t, app, adminReq(c.method, c.path, c.body, "sess-token")).StatusCode; got != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, c.want)
		}
		if got := send(t, app, adminReq(c.method, c.path, c.body, "")).StatusCode; got != 401 {
			t.Errorf("%s %s without cookie: %d", c.method, c.path, got)
		}
	}
	resp := send(t, app, adminReq("GET", "/me/sessions", "", "sess-token"))
	var list []sessionDTO
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil || len(list) != 2 || !list[0].Current || list[0].IP != "100.64.0.7" {
		t.Fatalf("sessions = %+v %v", list, err)
	}
}

func TestLoginRateLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.LoginMax = 2
	app, _ := newAdminServer(t, limits)
	var last int
	for range 3 {
		last = send(t, app, adminReq("POST", "/login", `{"username":"ops","password":"x"}`, "")).StatusCode
	}
	if last != 429 {
		t.Fatalf("third login: %d", last)
	}
}

func TestFindingsQueryParsing(t *testing.T) {
	app, d := newAdminServer(t, DefaultLimits())
	resp := send(t, app, adminReq("GET", "/findings?client=a&host_id=3&severity=CRITICAL&status=open&q=openssl&sort=first_seen&page=2&page_size=25", "", "sess-token"))
	var page struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
		Page  int              `json:"page"`
	}
	json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != 200 || page.Total != 1 || page.Page != 2 || page.Items[0]["status"] != "open" {
		t.Fatalf("status=%d page=%+v", resp.StatusCode, page)
	}
	want := domain.FindingFilter{Client: "a", HostID: 3, Severity: "CRITICAL", Status: "open", Query: "openssl",
		Sort: "first_seen", Page: 2, PageSize: 25}
	if d.filter != want {
		t.Fatalf("filter = %+v", d.filter)
	}
	for _, q := range []string{"sort=evil", "severity=SEVERE", "host_id=abc", "status=done"} {
		if got := send(t, app, adminReq("GET", "/findings?"+q, "", "sess-token")).StatusCode; got != 400 {
			t.Errorf("%s: %d", q, got)
		}
	}
}

func TestScanConfigEndpoint(t *testing.T) {
	app, d := newAdminServer(t, DefaultLimits())
	if got := send(t, app, adminReq("PUT", "/clients/a/scan-config", `{"command":"rm -rf /"}`, "sess-token")).StatusCode; got != 400 {
		t.Fatalf("unknown field: %d", got)
	}
	if d.scanCfg != nil {
		t.Fatal("invalid config stored")
	}
	resp := send(t, app, adminReq("PUT", "/clients/a/scan-config", `{"severity":["CRITICAL"]}`, "sess-token"))
	if resp.StatusCode != 200 || string(d.scanCfg) != `{"severity":["CRITICAL"]}` {
		t.Fatalf("status=%d stored=%s", resp.StatusCode, d.scanCfg)
	}
}

func TestClientsScanConfigJSON(t *testing.T) {
	app, _ := newAdminServer(t, DefaultLimits())
	resp := send(t, app, adminReq("GET", "/clients", "", "sess-token"))
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"scan_config":null`) || !strings.Contains(string(body), `"scan_config":{"timeout":"45m"}`) {
		t.Fatalf("body = %s", body)
	}
}
