package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func createMcpToken(t *testing.T, cookie, name string) model.CreateMcpTokenResponse {
	t.Helper()
	code, b := adminDo(t, "POST", "/mcp-tokens", fmt.Sprintf(`{"name":%q}`, name), cookie)
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
