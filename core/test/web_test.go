package test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/config"
	"netra-vuln/core/internal/delivery/http/middleware"
)

// withConfig sets viper keys for one app build and restores them afterwards.
func withConfig(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		old := viperCfg.GetString(k)
		viperCfg.Set(k, v)
		t.Cleanup(func() { viperCfg.Set(k, old) })
	}
}

func TestDashboardServing(t *testing.T) {
	ClearAll(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>spa"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app-1.js"), []byte("js"), 0o644))
	withConfig(t, map[string]string{"web.dashboard_dir": dir})
	a := newApp(testLimits)

	resp, body := send(t, a, httptest.NewRequest("GET", "/hosts/12", nil)) // client route
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "<!doctype html>spa", string(body))
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'self'")
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

	resp, _ = send(t, a, httptest.NewRequest("GET", "/assets/app-1.js", nil))
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Cache-Control"), "immutable")

	for _, p := range []string{"/api/admin/v1/nope", "/api/nope"} {
		resp, body = send(t, a, httptest.NewRequest("GET", p, nil))
		assert.NotEqual(t, "<!doctype html>spa", string(body), p+": API paths must not return the SPA")
	}
}

func TestAdminAllowCIDRs(t *testing.T) {
	ClearAll(t)
	// app.Test requests come from 0.0.0.0, outside this list.
	withConfig(t, map[string]string{"web.admin_allow_cidrs": "10.0.0.0/8, fd00::/8", "web.dashboard_dir": t.TempDir()})
	a := newApp(testLimits)

	for _, req := range []*http.Request{
		adminReq("POST", "/login", `{"username":"x","password":"y"}`, ""),
		adminReq("GET", "/me", "", ""),
		httptest.NewRequest("POST", "/mcp", nil),
		httptest.NewRequest("GET", "/", nil),
	} {
		resp, _ := send(t, a, req)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, req.URL.Path)
	}
	resp, _ := send(t, a, httptest.NewRequest("GET", "/healthz", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "agents are never restricted")

	_, err := middleware.ParseCIDRs("10.0.0.0/8 nope")
	assert.Error(t, err)
}

func TestBackup(t *testing.T) {
	ClearAll(t)
	enrollHost(t, "acme", "web-01")
	file := filepath.Join(t.TempDir(), "copy.db")
	require.NoError(t, config.Backup(db, file))
	fi, err := os.Stat(file)
	require.NoError(t, err)
	assert.Positive(t, fi.Size())
	assert.Error(t, config.Backup(db, file), "never overwrites an existing backup")
}
