package test

import (
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/model"
)

// withInstall rebuilds the app with the installer settings; the default app has none.
func withInstall(t *testing.T, publicURL, version string) {
	t.Helper()
	viperCfg.Set("web.public_url", publicURL)
	viperCfg.Set("agent.version", version)
	app = newApp(testLimits)
	t.Cleanup(func() {
		viperCfg.Set("web.public_url", "")
		viperCfg.Set("agent.version", "")
		app = newApp(testLimits)
	})
}

func getScript(t *testing.T, a *fiber.App) (int, string) {
	t.Helper()
	resp, body := send(t, a, httptest.NewRequest("GET", "/install.sh", nil))
	return resp.StatusCode, string(body)
}

func TestInstallScript(t *testing.T) {
	ClearAll(t)
	code, _ := getScript(t, app)
	assert.Equal(t, 404, code, "disabled without settings")

	withInstall(t, "https://vuln.example.com/", "v0.3.0")
	resp, body := send(t, app, httptest.NewRequest("GET", "/install.sh", nil))
	require.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/x-shellscript")
	script := string(body)
	assert.Contains(t, script, "releases/download/v0.3.0'")
	assert.Contains(t, script, "install -central-url 'https://vuln.example.com' -client-id \"$client\"")
	assert.Contains(t, script, "sha256sum -c -")

	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "sh -n: %s", out)

	cookie := adminSession(t)
	info, _ := getData[model.InstallInfoResponse](t, cookie, "/install")
	assert.Equal(t, model.InstallInfoResponse{Enabled: true, PublicURL: "https://vuln.example.com", AgentVersion: "v0.3.0"}, info)
}

func TestInstallScriptRejectsUnsafeSettings(t *testing.T) {
	for _, c := range [][2]string{
		{"https://vuln.example.com/x'; rm -rf / #", "v0.3.0"},
		{"ftp://vuln.example.com", "v0.3.0"},
		{"https://vuln.example.com", "latest"},
		{"https://vuln.example.com", "v0.3.0'"},
	} {
		withInstall(t, c[0], c[1])
		code, _ := getScript(t, app)
		assert.Equal(t, 404, code, "%q", c)
	}
}

func TestRotateEnrollToken(t *testing.T) {
	ClearAll(t)
	old := newClient(t, "client_a")
	cookie := adminSession(t)

	code, _ := adminDo(t, "POST", "/clients/client_a/enroll-token", "", "")
	assert.Equal(t, 401, code, "needs a session")
	req := adminReq("POST", "/clients/client_a/enroll-token", "", cookie)
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := send(t, app, req)
	assert.Equal(t, 403, resp.StatusCode, "cross-origin")
	code, _ = adminDo(t, "POST", "/clients/nope/enroll-token", "", cookie)
	assert.Equal(t, 404, code, "unknown client")

	code, b := adminDo(t, "POST", "/clients/client_a/enroll-token", "", cookie)
	require.Equal(t, 200, code)
	var res model.WebResponse[model.EnrollTokenResponse]
	require.NoError(t, json.Unmarshal(b, &res))
	assert.Len(t, res.Data.EnrollToken, 64)

	code, _ = enrollStatus(t, "client_a", old, "vm1")
	assert.Equal(t, 401, code, "old token revoked")
	code, _ = enrollStatus(t, "client_a", res.Data.EnrollToken, "vm1")
	assert.Equal(t, 200, code, "new token works")
}
