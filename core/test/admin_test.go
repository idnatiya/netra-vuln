package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"netra-vuln/core/internal/usecase"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/model"
)

func TestLoginSetsHardenedCookie(t *testing.T) {
	ClearAll(t)
	newAdmin(t, "ops")
	resp, body := send(t, app, adminReq("POST", "/login", `{"username":"ops","password":"`+password+`"}`, ""))
	require.Equal(t, 200, resp.StatusCode)
	c := resp.Cookies()[0]
	assert.Equal(t, "vuln_session", c.Name)
	assert.Len(t, c.Value, 64)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Equal(t, "/api/admin", c.Path)
	var me model.WebResponse[model.MeResponse]
	require.NoError(t, json.Unmarshal(body, &me))
	assert.Equal(t, "ops", me.Data.Username)
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM admin_sessions WHERE token_hash = ?", usecase.HashToken(c.Value)),
		"session token must be stored as its SHA-256 hash")

	for _, creds := range [][2]string{{"ops", "wrong password!!"}, {"nobody", password}, {"", ""}} {
		code, b := adminDo(t, "POST", "/login", string(mustJSON(map[string]string{"username": creds[0], "password": creds[1]})), "")
		assert.Equal(t, 401, code, "login %v", creds)
		assert.Contains(t, string(b), `"errors"`, "admin errors use the WebResponse envelope")
	}

	require.NoError(t, db.Exec("UPDATE admin_users SET disabled_at = ? WHERE username = 'ops'", time.Now().UTC()).Error)
	code, _ := adminDo(t, "POST", "/login", `{"username":"ops","password":"`+password+`"}`, "")
	assert.Equal(t, 401, code, "disabled user")
}

func TestAdminRequiresSession(t *testing.T) {
	ClearAll(t)
	cookie := adminSession(t)
	for _, path := range []string{"/me", "/overview", "/findings", "/components", "/hosts", "/clients", "/trend", "/oldest-cves",
		"/distribution", "/me/sessions"} {
		code, _ := adminDo(t, "GET", path, "", "")
		assert.Equal(t, 401, code, "%s without cookie", path)
		code, _ = adminDo(t, "GET", path, "", "forged")
		assert.Equal(t, 401, code, "%s with forged cookie", path)
		code, _ = adminDo(t, "GET", path, "", cookie)
		assert.Equal(t, 200, code, "%s with session", path)
	}
}

func TestSessionLifecycle(t *testing.T) {
	ClearAll(t)
	cookie := adminSession(t)
	code, _ := adminDo(t, "GET", "/me", "", cookie)
	require.Equal(t, 200, code)

	require.NoError(t, db.Exec("UPDATE admin_sessions SET expires_at = ?", time.Now().UTC().Add(-time.Second)).Error)
	code, _ = adminDo(t, "GET", "/me", "", cookie)
	assert.Equal(t, 401, code, "expired session")

	cookie = login(t, "ops", password)
	resp, _ := send(t, app, adminReq("POST", "/logout", "", cookie))
	require.Equal(t, 204, resp.StatusCode)
	assert.Empty(t, resp.Cookies()[0].Value, "logout clears the cookie")
	code, _ = adminDo(t, "GET", "/me", "", cookie)
	assert.Equal(t, 401, code, "after logout")

	require.NoError(t, uc.AdminUser.SetPassword(context.Background(), &model.CreateAdminRequest{Username: "ops", Password: "another long password"}))
	code, _ = adminDo(t, "POST", "/login", `{"username":"ops","password":"`+password+`"}`, "")
	assert.Equal(t, 401, code, "old password still works")
	login(t, "ops", "another long password")

	err := uc.AdminUser.Create(context.Background(), &model.CreateAdminRequest{Username: "eve", Password: "short"})
	assert.Error(t, err, "short password")
	assert.Equal(t, 0, count(t, "SELECT COUNT(*) FROM admin_users WHERE password_hash LIKE ?", "%"+password+"%"), "plaintext password")
}

func TestAdminRejectsCrossOrigin(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	ingest(t, h, "ok", cves("CVE-1")...)
	var id int64
	db.Raw("SELECT id FROM findings").Scan(&id)
	cookie := adminSession(t)
	path := fmt.Sprintf("/findings/%d", id)

	for _, o := range []string{"", "https://evil.example", "null"} {
		req := adminReq("PATCH", path, `{"status":"accepted"}`, cookie)
		if o == "" {
			req.Header.Del("Origin")
		} else {
			req.Header.Set("Origin", o)
		}
		resp, _ := send(t, app, req)
		assert.Equal(t, 403, resp.StatusCode, "origin %q", o)
	}
	assert.Zero(t, count(t, "SELECT COUNT(*) FROM findings WHERE status = 'accepted'"), "cross-origin request reached the handler")
	code, _ := adminDo(t, "PATCH", path, `{"status":"accepted","note":"risk accepted until Q3"}`, cookie)
	assert.Equal(t, 204, code, "same origin")
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM findings WHERE status = 'accepted' AND note = 'risk accepted until Q3'"))
}

func TestTriageFinding(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	ingest(t, h, "ok", cves("CVE-1")...)
	var id int64
	db.Raw("SELECT id FROM findings").Scan(&id)
	cookie := adminSession(t)
	path := fmt.Sprintf("/findings/%d", id)
	for body, want := range map[string]int{
		`{"status":"fixed"}`: 400,
		`{"status":"open","note":"` + strings.Repeat("x", 2001) + `"}`: 400,
		`{"status":"false_positive"}`:                                  204,
	} {
		code, _ := adminDo(t, "PATCH", path, body, cookie)
		assert.Equal(t, want, code, body[:min(len(body), 40)])
	}
	code, _ := adminDo(t, "PATCH", "/findings/999999999", `{"status":"open"}`, cookie)
	assert.Equal(t, 404, code, "missing")
	code, _ = adminDo(t, "PATCH", "/findings/x", `{"status":"open"}`, cookie)
	assert.Equal(t, 400, code, "bad id")
}

func TestAccountSessions(t *testing.T) {
	ClearAll(t)
	newAdmin(t, "ops")
	newAdmin(t, "eve")
	ua := strings.Repeat("é", 200) // 400 bytes
	req := adminReq("POST", "/login", `{"username":"ops","password":"`+password+`"}`, "")
	req.Header.Set("User-Agent", ua)
	resp, _ := send(t, app, req)
	require.Equal(t, 200, resp.StatusCode)
	me := resp.Cookies()[0].Value
	other := login(t, "ops", password)
	eve := login(t, "eve", password)

	list, _ := getData[[]model.SessionResponse](t, me, "/me/sessions")
	require.Len(t, list, 2)
	var meID, otherID int64
	for _, s := range list {
		if s.Current {
			meID = s.ID
			assert.LessOrEqual(t, len(s.UserAgent), 255)
			assert.True(t, utf8.ValidString(s.UserAgent), "user agent cut mid-rune")
		} else {
			otherID = s.ID
		}
	}
	require.NotZero(t, meID)
	var eveID int64
	db.Raw("SELECT s.id FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id WHERE u.username = 'eve'").Scan(&eveID)

	code, _ := adminDo(t, "DELETE", fmt.Sprintf("/me/sessions/%d", meID), "", me)
	assert.Equal(t, 409, code, "revoke current")
	code, _ = adminDo(t, "DELETE", fmt.Sprintf("/me/sessions/%d", eveID), "", me)
	assert.Equal(t, 404, code, "another admin's session")
	code, _ = adminDo(t, "DELETE", "/me/sessions/x", "", me)
	assert.Equal(t, 400, code)

	for body, want := range map[string]int{
		`{"current_password":"wrong password!!","new_password":"brand new passphrase"}`: 400,
		`{"current_password":"` + password + `","new_password":"short"}`:                400,
	} {
		code, _ := adminDo(t, "POST", "/me/password", body, me)
		assert.Equal(t, want, code, body)
	}
	res := model.WebResponse[model.CountResponse]{}
	code, b := adminDo(t, "POST", "/me/password", `{"current_password":"`+password+`","new_password":"brand new passphrase"}`, me)
	require.Equal(t, 200, code, string(b))
	require.NoError(t, json.Unmarshal(b, &res))
	assert.Equal(t, 1, res.Data.Count, "other sessions signed out")

	code, _ = adminDo(t, "GET", "/me", "", other)
	assert.Equal(t, 401, code, "other session survived the password change")
	code, _ = adminDo(t, "GET", "/me", "", me)
	assert.Equal(t, 200, code, "current session ended")
	code, _ = adminDo(t, "GET", "/me", "", eve)
	assert.Equal(t, 200, code, "another admin was signed out")

	login(t, "ops", "brand new passphrase")
	code, b = adminDo(t, "DELETE", "/me/sessions", "", me)
	require.Equal(t, 200, code)
	require.NoError(t, json.Unmarshal(b, &res))
	assert.Equal(t, 1, res.Data.Count, "revoke others")
	_ = otherID
}

func TestFindingsQueryValidation(t *testing.T) {
	ClearAll(t)
	cookie := adminSession(t)
	for _, q := range []string{"sort=evil", "severity=SEVERE", "host_id=abc", "status=done", "page=x", "component_kind=lib"} {
		code, b := adminDo(t, "GET", "/findings?"+q, "", cookie)
		assert.Equal(t, 400, code, q)
		assert.Contains(t, string(b), `"errors"`, q)
	}
}

func TestScanConfigEndpoint(t *testing.T) {
	ClearAll(t)
	newClient(t, "client_a")
	newClient(t, "client_b")
	cookie := adminSession(t)
	code, _ := adminDo(t, "PUT", "/clients/client_a/scan-config", `{"command":"rm -rf /"}`, cookie)
	assert.Equal(t, 400, code, "unknown field")
	assert.Zero(t, count(t, "SELECT COUNT(*) FROM clients WHERE scan_config IS NOT NULL"), "invalid config stored")
	code, _ = adminDo(t, "PUT", "/clients/nope/scan-config", `{"timeout":"45m"}`, cookie)
	assert.Equal(t, 404, code, "unknown client")

	code, b := adminDo(t, "PUT", "/clients/client_b/scan-config", `{"timeout":"45m"}`, cookie)
	require.Equal(t, 200, code)
	assert.JSONEq(t, `{"data":{"timeout":"45m"}}`, string(b))

	code, b = adminDo(t, "GET", "/clients", "", cookie)
	require.Equal(t, 200, code)
	assert.Contains(t, string(b), `"scan_config":null`)
	assert.Contains(t, string(b), `"scan_config":{"timeout":"45m"}`)
}

func TestCreateClient(t *testing.T) {
	ClearAll(t)
	cookie := adminSession(t)
	code, b := adminDo(t, "POST", "/clients", `{"name":"acme-01"}`, cookie)
	require.Equal(t, 201, code)
	var res model.WebResponse[model.CreateClientResponse]
	require.NoError(t, json.Unmarshal(b, &res))
	assert.Equal(t, "acme-01", res.Data.Name)
	code, _ = adminDo(t, "POST", "/clients", `{"name":"acme-01"}`, cookie)
	assert.Equal(t, 409, code, "duplicate")
	for _, bad := range []string{"", "Client", "-a", "a b", strings.Repeat("a", 65)} {
		code, _ := adminDo(t, "POST", "/clients", string(mustJSON(map[string]string{"name": bad})), cookie)
		assert.Equal(t, 400, code, "%q", bad)
	}
}

func TestDeleteClient(t *testing.T) {
	ClearAll(t)
	newClient(t, "empty")
	cookie := adminSession(t)
	code, _ := adminDo(t, "DELETE", "/clients/empty", "", "")
	assert.Equal(t, 401, code)
	code, _ = adminDo(t, "DELETE", "/clients/empty", "", cookie)
	assert.Equal(t, 204, code)
	code, _ = adminDo(t, "DELETE", "/clients/empty", "", cookie)
	assert.Equal(t, 404, code)
	h := enrollHost(t, "occupied", "vm1")
	code, _ = adminDo(t, "DELETE", "/clients/occupied", "", cookie)
	assert.Equal(t, 409, code)
	code, _ = adminDo(t, "POST", fmt.Sprintf("/hosts/%d/revoke", h.ID), "", cookie)
	require.Equal(t, 204, code)
	code, _ = adminDo(t, "DELETE", "/clients/occupied", "", cookie)
	assert.Equal(t, 409, code)
}

func TestDeleteHost(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	other := enrollHost(t, "client_b", "vm2")
	ingest(t, h, "ok", cves("CVE-A")...)
	ingest(t, other, "ok", cves("CVE-B")...)
	cookie := adminSession(t)
	path := fmt.Sprintf("/hosts/%d", h.ID)
	code, _ := adminDo(t, "DELETE", path, "", "")
	assert.Equal(t, 401, code)
	req := adminReq("DELETE", path, "", cookie)
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := send(t, app, req)
	assert.Equal(t, 403, resp.StatusCode)
	code, _ = adminDo(t, "DELETE", "/hosts/nope", "", cookie)
	assert.Equal(t, 400, code)
	code, _ = adminDo(t, "DELETE", path, "", cookie)
	assert.Equal(t, 409, code, "active host must be revoked first")
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM scans WHERE host_id = ?", h.ID))
	code, _ = adminDo(t, "POST", path+"/revoke", "", cookie)
	require.Equal(t, 204, code)
	code, _ = adminDo(t, "DELETE", path, "", cookie)
	require.Equal(t, 204, code)
	for _, table := range []string{"scans", "findings"} {
		assert.Equal(t, 0, count(t, "SELECT COUNT(*) FROM "+table+" WHERE host_id = ?", h.ID))
		assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM "+table+" WHERE host_id = ?", other.ID))
	}
	assert.Equal(t, 0, count(t, "SELECT COUNT(*) FROM hosts WHERE id = ?", h.ID))
	code, _ = adminDo(t, "DELETE", path, "", cookie)
	assert.Equal(t, 404, code)
	code, _ = adminDo(t, "DELETE", "/clients/client_a", "", cookie)
	assert.Equal(t, 204, code, "client can be deleted after its last host")
}
