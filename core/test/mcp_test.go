package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/delivery/http/route"
	"netra-vuln/core/internal/model"
)

// mcpCall sends one JSON-RPC tools/call to /mcp and returns the HTTP status and
// the tool's structured content (nil unless the call succeeded).
func mcpCall(t *testing.T, token, tool string, args any) (int, map[string]any) {
	t.Helper()
	body := mustJSON(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args}})
	req := httptest.NewRequest("POST", origin+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, b := send(t, app, req)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var res struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(b, &res), string(b))
	require.False(t, res.Result.IsError, string(b))
	return resp.StatusCode, res.Result.StructuredContent
}

func createMcpToken(t *testing.T, cookie, name string, canTriage ...bool) model.CreateMcpTokenResponse {
	t.Helper()
	code, b := adminDo(t, "POST", "/mcp-tokens", fmt.Sprintf(`{"name":%q,"can_triage":%t}`, name, len(canTriage) > 0 && canTriage[0]), cookie)
	require.Equal(t, http.StatusCreated, code, string(b))
	var res model.WebResponse[model.CreateMcpTokenResponse]
	require.NoError(t, json.Unmarshal(b, &res))
	require.Len(t, res.Data.Token, 64)
	return res.Data
}

func TestMcpTokens(t *testing.T) {
	ClearAll(t)
	cookie := adminSession(t)

	code, _ := adminDo(t, "POST", "/mcp-tokens", `{"name":"  "}`, cookie)
	assert.Equal(t, http.StatusBadRequest, code, "blank name")
	code, _ = adminDo(t, "POST", "/mcp-tokens", `{"name":"x"}`, "")
	assert.Equal(t, http.StatusUnauthorized, code, "needs a session")

	tok := createMcpToken(t, cookie, "laptop")
	list, _ := getData[[]model.McpTokenResponse](t, cookie, "/mcp-tokens")
	require.Len(t, list, 1)
	assert.Equal(t, "laptop", list[0].Name)
	assert.Nil(t, list[0].LastUsedAt)
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM mcp_tokens WHERE token_hash = UNHEX(SHA2(?, 256))", tok.Token), "stored hashed")

	code, _ = mcpCall(t, "", "list_clients", map[string]any{})
	assert.Equal(t, http.StatusUnauthorized, code, "no token")
	code, _ = mcpCall(t, "wrong", "list_clients", map[string]any{})
	assert.Equal(t, http.StatusUnauthorized, code, "unknown token")
	code, _ = mcpCall(t, tok.Token, "list_clients", map[string]any{})
	assert.Equal(t, http.StatusOK, code)
	list, _ = getData[[]model.McpTokenResponse](t, cookie, "/mcp-tokens")
	assert.NotNil(t, list[0].LastUsedAt, "use is recorded")

	// Another admin cannot see or revoke it.
	newAdmin(t, "other")
	other := login(t, "other", password)
	otherList, _ := getData[[]model.McpTokenResponse](t, other, "/mcp-tokens")
	assert.Empty(t, otherList)
	code, _ = adminDo(t, "DELETE", fmt.Sprintf("/mcp-tokens/%d", tok.ID), "", other)
	assert.Equal(t, http.StatusNotFound, code)

	code, _ = adminDo(t, "DELETE", fmt.Sprintf("/mcp-tokens/%d", tok.ID), "", cookie)
	require.Equal(t, http.StatusNoContent, code)
	code, _ = mcpCall(t, tok.Token, "list_clients", map[string]any{})
	assert.Equal(t, http.StatusUnauthorized, code, "revoked token")
	list, _ = getData[[]model.McpTokenResponse](t, cookie, "/mcp-tokens")
	assert.Empty(t, list)
}

func TestMcpTools(t *testing.T) {
	ClearAll(t)
	a := enrollHost(t, "client_a", "web-1")
	b := enrollHost(t, "client_b", "db-1")
	ingest(t, a, "ok", vuln("CVE-1", "CRITICAL", "openssl"), vuln("CVE-2", "HIGH", "libc6"))
	ingest(t, b, "ok", vuln("CVE-1", "CRITICAL", "openssl"))
	tok := createMcpToken(t, adminSession(t), "laptop").Token

	_, out := mcpCall(t, tok, "list_clients", map[string]any{})
	assert.Len(t, out["clients"], 2)

	_, out = mcpCall(t, tok, "list_hosts", map[string]any{"client": "client_a"})
	hosts := out["hosts"].([]any)
	require.Len(t, hosts, 1)
	assert.Equal(t, "web-1", hosts[0].(map[string]any)["hostname"])

	_, out = mcpCall(t, tok, "search_findings", map[string]any{"query": "CVE-1"})
	assert.Len(t, out["findings"], 2, "CVE-1 on both hosts")
	assert.EqualValues(t, 25, out["paging"].(map[string]any)["size"])

	_, out = mcpCall(t, tok, "search_findings", map[string]any{"client": "client_a", "severity": "HIGH"})
	require.Len(t, out["findings"], 1)
	assert.Equal(t, "CVE-2", out["findings"].([]any)[0].(map[string]any)["cve"])

	_, out = mcpCall(t, tok, "host_components", map[string]any{"host_id": a.ID})
	assert.NotEmpty(t, out["components"])
}

// mcpRaw sends one JSON-RPC request to /mcp and returns the decoded response.
func mcpRaw(t *testing.T, token, method string, params any) map[string]any {
	t.Helper()
	body := mustJSON(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest("POST", origin+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, b := send(t, app, req)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(b))
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out), string(b))
	return out
}

func toolNames(t *testing.T, token string) []string {
	t.Helper()
	var names []string
	for _, tool := range mcpRaw(t, token, "tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func TestMcpTriage(t *testing.T) {
	ClearAll(t)
	a := enrollHost(t, "client_a", "web-1")
	ingest(t, a, "ok", vuln("CVE-1", "CRITICAL", "openssl"), vuln("CVE-2", "HIGH", "libc6"))
	cookie := adminSession(t)
	readTok := createMcpToken(t, cookie, "reader").Token
	triageTok := createMcpToken(t, cookie, "laptop-codex", true)
	assert.True(t, triageTok.CanTriage)

	// Read-only tokens do not even see the triage tools.
	assert.NotContains(t, toolNames(t, readTok), "triage_finding")
	assert.Contains(t, toolNames(t, triageTok.Token), "triage_finding")
	assert.Contains(t, toolNames(t, triageTok.Token), "triage_component")
	res := mcpRaw(t, readTok, "tools/call", map[string]any{"name": "triage_finding",
		"arguments": map[string]any{"finding_id": 1, "status": "accepted"}})
	assert.NotNil(t, res["error"], "unknown tool for a read-only token")

	var fid int64
	require.NoError(t, db.Raw("SELECT id FROM findings WHERE host_id = ? AND cve = 'CVE-1'", a.ID).Scan(&fid).Error)
	_, out := mcpCall(t, triageTok.Token, "triage_finding", map[string]any{"finding_id": fid, "status": "accepted", "note": "patch next week"})
	assert.EqualValues(t, 1, out["updated"])
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM findings WHERE id = ? AND status = 'accepted' AND note = ?", fid,
		"patch next week [via MCP: laptop-codex]"))

	// Bad input is a tool error, not a change.
	res = mcpRaw(t, triageTok.Token, "tools/call", map[string]any{"name": "triage_finding",
		"arguments": map[string]any{"finding_id": fid, "status": "ignored"}})
	assert.Equal(t, true, res["result"].(map[string]any)["isError"])

	// Component bulk verdict, with an empty note.
	_, comps := mcpCall(t, triageTok.Token, "host_components", map[string]any{"host_id": a.ID})
	c := comps["components"].([]any)[0].(map[string]any)
	_, out = mcpCall(t, triageTok.Token, "triage_component", map[string]any{"host_id": a.ID, "kind": c["kind"], "key": c["key"], "status": "false_positive"})
	assert.Positive(t, out["updated"])
	assert.Positive(t, count(t, "SELECT COUNT(*) FROM findings WHERE status = 'false_positive' AND note = '[via MCP: laptop-codex]'"))
}

func TestMcpPagingAndLimits(t *testing.T) {
	ClearAll(t)
	a := enrollHost(t, "client_a", "web-1")
	var many []string
	for i := range 130 {
		many = append(many, fmt.Sprintf("CVE-%d", i))
	}
	ingest(t, a, "ok", cves(many...)...)
	tok := createMcpToken(t, adminSession(t), "laptop").Token

	_, out := mcpCall(t, tok, "search_findings", map[string]any{"page_size": 100})
	assert.Len(t, out["findings"], 100)
	_, out = mcpCall(t, tok, "search_findings", map[string]any{"page_size": 500})
	assert.Len(t, out["findings"], 100, "clamped")
	_, out = mcpCall(t, tok, "search_findings", map[string]any{})
	assert.Len(t, out["findings"], 25, "default")

	// MCP has its own limit: exhausting it never throttles agents.
	limited := newApp(route.Limits{Window: time.Hour, PerHostMax: 1000, EnrollMax: 1000, AuthMax: 3, LoginMax: 1000, McpMax: 2})
	defer func() { app = newApp(testLimits) }()
	prev := app
	app = limited
	codes := []int{}
	for range 3 {
		c, _ := mcpCall(t, tok, "list_clients", map[string]any{})
		codes = append(codes, c)
	}
	app = prev
	assert.Equal(t, []int{200, 200, 429}, codes)
	resp, _ := send(t, limited, agentReq("GET", "/api/v1/config", a.Token, nil, false))
	assert.Equal(t, 200, resp.StatusCode, "agent unaffected")
}
