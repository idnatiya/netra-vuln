package test

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/model"
)

func hostsByName(t *testing.T, cookie, path string) map[string]model.HostResponse {
	t.Helper()
	hosts, _ := getData[[]model.HostResponse](t, cookie, path)
	out := map[string]model.HostResponse{}
	for _, h := range hosts {
		out[h.Hostname] = h
	}
	return out
}

func TestDashboardQueries(t *testing.T) {
	ClearAll(t)
	a := enrollHost(t, "client_a", "web-1")
	b := enrollHost(t, "client_b", "db-1")
	cookie := adminSession(t)

	ingest(t, a, "ok", vuln("CVE-1", "CRITICAL", "openssl"), vuln("CVE-2", "HIGH", "libc6"), vuln("CVE-3", "HIGH", "zlib"))
	ingest(t, b, "ok", vuln("CVE-1", "CRITICAL", "openssl"), vuln("CVE-4", "HIGH", "curl"))
	hb := mustJSON(wire.Heartbeat{ClientID: a.Client, Host: wire.Host{Hostname: a.Hostname, OSName: "Ubuntu", OSVersion: "24.04",
		AgentVersion: "0.2.0", UnattendedUpgradesEnabled: true}})
	require.Equal(t, 204, agentStatus(t, "POST", "/api/v1/heartbeat", a.Token, hb, false))

	// Triage: accepted findings leave the open counts but keep their verdict across re-scans.
	page, paging := getData[[]model.FindingResponse](t, cookie, "/findings?client=client_a&q=zlib")
	require.Len(t, page, 1)
	assert.EqualValues(t, 1, paging.TotalItem)
	zlibID := page[0].ID
	code, _ := adminDo(t, "PATCH", fmt.Sprintf("/findings/%d", zlibID), `{"status":"accepted","note":"vendor patch pending"}`, cookie)
	require.Equal(t, 204, code)
	ingest(t, a, "ok", vuln("CVE-1", "CRITICAL", "openssl"), vuln("CVE-2", "HIGH", "libc6"), vuln("CVE-3", "HIGH", "zlib"))
	page, _ = getData[[]model.FindingResponse](t, cookie, "/findings?status=accepted")
	require.Len(t, page, 1, "triage after re-scan")
	assert.Equal(t, zlibID, page[0].ID)
	assert.Equal(t, "vendor patch pending", page[0].Note)

	ov, _ := getData[model.OverviewResponse](t, cookie, "/overview")
	assert.Equal(t, model.TotalsResponse{Clients: 2, Hosts: 2, OpenCritical: 2, OpenHigh: 2, Accepted: 1, StaleHosts: 1, AutoUpdateOff: 2}, ov.Totals) // the re-scan report overwrote the heartbeat's auto-update flag
	hosts := hostsByName(t, cookie, "/hosts")
	if h := hosts["web-1"]; assert.Contains(t, hosts, "web-1") {
		assert.Equal(t, []int{1, 1, 1}, []int{h.OpenCritical, h.OpenHigh, h.Accepted})
		assert.False(t, h.StaleScan || h.StaleHeartbeat, "web-1 = %+v", h)
	}
	assert.True(t, hosts["db-1"].StaleHeartbeat, "scanned, never sent a heartbeat")
	assert.False(t, hosts["db-1"].StaleScan)
	assert.Len(t, hostsByName(t, cookie, "/hosts?client=client_b"), 1)

	// Filters, ordering, and paging.
	_, paging = getData[[]model.FindingResponse](t, cookie, "/findings?severity=CRITICAL")
	assert.EqualValues(t, 2, paging.TotalItem)
	page, paging = getData[[]model.FindingResponse](t, cookie, "/findings?size=2&page=2")
	assert.Len(t, page, 2)
	assert.Equal(t, model.PageMetadata{Page: 2, Size: 2, TotalItem: 5, TotalPage: 3}, *paging)
	page, _ = getData[[]model.FindingResponse](t, cookie, "/findings")
	assert.Equal(t, "CRITICAL", page[0].Severity, "most severe first")
	_, paging = getData[[]model.FindingResponse](t, cookie, "/findings?q="+url.QueryEscape("100%_"))
	assert.Zero(t, paging.TotalItem, "wildcards are escaped")

	// Trend: last scan per host per day, summed.
	trend, _ := getData[[]model.TrendResponse](t, cookie, "/trend?days=7")
	require.Len(t, trend, 1)
	assert.Equal(t, model.TrendResponse{Day: time.Now().UTC().Format("2006-01-02"), Critical: 2, High: 3}, trend[0])

	oldest, _ := getData[[]model.CVEAgeResponse](t, cookie, "/oldest-cves?limit=10")
	require.Len(t, oldest, 3)
	assert.Equal(t, "CVE-1", oldest[0].CVE)
	assert.Equal(t, 2, oldest[0].Hosts)

	dist, _ := getData[model.DistributionResponse](t, cookie, "/distribution")
	assert.Equal(t, []model.KeyCountResponse{{Key: "Ubuntu 24.04", N: 2}}, dist.OS)

	// Revoked hosts drop out of findings and totals.
	code, _ = adminDo(t, "POST", fmt.Sprintf("/hosts/%d/revoke", b.ID), "", cookie)
	require.Equal(t, 204, code)
	page, paging = getData[[]model.FindingResponse](t, cookie, "/findings")
	assert.EqualValues(t, 3, paging.TotalItem, "web-1 only: CVE-1, CVE-2 open + CVE-3 accepted")
	for _, f := range page {
		assert.NotEqual(t, "db-1", f.Hostname, "revoked host still listed")
	}
	ov, _ = getData[model.OverviewResponse](t, cookie, "/overview")
	assert.Equal(t, 1, ov.Totals.Hosts)
}

func TestComponents(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "web-1")
	cookie := adminSession(t)

	kernel := func(cve, pkg string) wire.Finding {
		f := vuln(cve, "HIGH", pkg)
		f.Type, f.Target, f.InstalledVersion, f.FixedVersion = "ubuntu", "web-1 (ubuntu 24.04)", "6.8.0-124.124", "6.8.0-147.147"
		return f
	}
	app := func(cve, pkg, path string) wire.Finding {
		f := vuln(cve, "CRITICAL", pkg)
		f.Type, f.Target, f.PkgPath = "composer-vendor", "PHP", path
		return f
	}
	ingest(t, h, "ok",
		kernel("CVE-1", "linux-libc-dev"), kernel("CVE-1", "linux-tools-common"), kernel("CVE-2", "linux-libc-dev"),
		app("CVE-9", "laravel/framework", "var/www/shop/vendor/composer/installed.json"),
		// Same package and version in a second app stays a separate finding.
		app("CVE-9", "laravel/framework", "var/www/blog/vendor/composer/installed.json"),
	)

	rows, _ := getData[[]model.ComponentResponse](t, cookie, "/components?client=client_a")
	require.Len(t, rows, 3)
	// Ordered by critical count first: the two apps, then the kernel group.
	k := rows[2]
	assert.Equal(t, "os", k.Kind)
	assert.Equal(t, []int{3, 2, 2}, []int{k.Findings, k.CVEs, k.PkgCount})
	assert.Equal(t, []string{"linux-libc-dev", "linux-tools-common"}, k.Packages)
	assert.Equal(t, []string{"ubuntu"}, k.Types)
	assert.Equal(t, "app", rows[0].Kind)
	assert.Equal(t, 1, rows[0].Critical)
	assert.NotEqual(t, rows[0].Key, rows[1].Key)

	page, paging := getData[[]model.FindingResponse](t, cookie, "/findings?component_kind=app&component="+url.QueryEscape("/var/www/shop"))
	require.EqualValues(t, 1, paging.TotalItem, "drill-down")
	assert.Equal(t, "var/www/shop/vendor/composer/installed.json", page[0].PkgPath)

	// Triage a whole component at once; it leaves the open counts.
	body := mustJSON(model.TriageComponentRequest{HostID: h.ID, Kind: "os", Key: k.Key, Status: "accepted", Note: "fallback kernel"})
	res, _ := adminDo(t, "POST", "/components/triage", string(body), cookie)
	require.Equal(t, 200, res)
	rows, _ = getData[[]model.ComponentResponse](t, cookie, fmt.Sprintf("/components?host_id=%d&status=open", h.ID))
	assert.Len(t, rows, 2, "open components after triage")
	code, _ := adminDo(t, "POST", "/components/triage", `{"host_id":1,"kind":"lib","status":"accepted"}`, cookie)
	assert.Equal(t, 400, code, "bad kind")

	// Last-scan changes: the first scan has nothing to compare against; a second
	// scan without the blog app resolves it and adds one new kernel CVE.
	hosts := hostsByName(t, cookie, "/hosts")
	assert.True(t, hosts["web-1"].FirstScan)
	assert.Equal(t, 5, hosts["web-1"].NewInLastScan)
	ingest(t, h, "ok",
		kernel("CVE-1", "linux-libc-dev"), kernel("CVE-1", "linux-tools-common"), kernel("CVE-2", "linux-libc-dev"),
		kernel("CVE-3", "linux-libc-dev"),
		app("CVE-9", "laravel/framework", "var/www/shop/vendor/composer/installed.json"),
	)
	hosts = hostsByName(t, cookie, "/hosts")
	assert.False(t, hosts["web-1"].FirstScan)
	assert.Equal(t, 1, hosts["web-1"].NewInLastScan)
	assert.Equal(t, 1, hosts["web-1"].ResolvedInLastScan)
}
