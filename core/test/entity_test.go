package test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/entity"
)

func TestReportNormalize(t *testing.T) {
	f := entity.Vulnerability{CVE: "CVE-1", Pkg: "openssl", InstalledVersion: "1", Target: "t", Severity: "HIGH"}
	long := f
	long.CVE, long.Title = "CVE-2", strings.Repeat("é", 2000)
	weird := f
	weird.CVE, weird.Severity = "CVE-3", "SUPER"

	r := entity.Report{Status: entity.StatusOK, Findings: []entity.Vulnerability{f, f, long, weird}}
	r.Normalize()
	require.Len(t, r.Findings, 3, "dedupe")
	assert.Equal(t, 1024, len([]rune(r.Findings[1].Title)))
	assert.Equal(t, "UNKNOWN", r.Findings[2].Severity)
	assert.Equal(t, entity.Counts{Total: 3, High: 2}, r.Counts())

	e := entity.Report{Status: entity.StatusError, Findings: []entity.Vulnerability{f}}
	e.Normalize()
	assert.Nil(t, e.Findings, "error report kept findings")
}

func TestReportValidate(t *testing.T) {
	now := time.Now()
	ok := entity.Report{Status: entity.StatusOK, ScannedAt: now, Findings: []entity.Vulnerability{{CVE: "CVE-1", Pkg: "p"}}}
	require.NoError(t, ok.Validate(now))
	for name, r := range map[string]entity.Report{
		"status":   {Status: "done", ScannedAt: now},
		"zero ts":  {Status: entity.StatusOK},
		"future":   {Status: entity.StatusOK, ScannedAt: now.Add(48 * time.Hour)},
		"no cve":   {Status: entity.StatusOK, ScannedAt: now, Findings: []entity.Vulnerability{{Pkg: "p"}}},
		"too many": {Status: entity.StatusOK, ScannedAt: now, Findings: make([]entity.Vulnerability, entity.MaxFindings+1)},
	} {
		assert.Error(t, r.Validate(now), name)
	}
}

func TestFindingKey(t *testing.T) {
	a := entity.Vulnerability{CVE: "CVE-1", Pkg: "ab", InstalledVersion: "c", Target: "t"}
	b := entity.Vulnerability{CVE: "CVE-1", Pkg: "a", InstalledVersion: "bc", Target: "t"} // same concatenation
	assert.False(t, bytes.Equal(a.Key(), b.Key()))
	assert.Len(t, a.Key(), 32)
	a2 := a
	a2.Title, a2.Severity, a2.FixedVersion = "other", "LOW", "9"
	assert.Equal(t, a.Key(), a2.Key(), "key must ignore non-identity fields")
	a3 := a
	a3.PkgPath = "x/y"
	assert.NotEqual(t, a.Key(), a3.Key(), "PkgPath must change the key")
}

func TestComponent(t *testing.T) {
	type V = entity.Vulnerability
	cases := []struct {
		v    V
		kind entity.ComponentKind
		key  string
	}{
		{V{Type: "ubuntu", Pkg: "linux-libc-dev", InstalledVersion: "6.8.0-124.124", FixedVersion: "6.8.0-147.147"}, entity.ComponentOS, "6.8.0-124.124"},
		// The fixed version differs per CVE; the kernel stays one component.
		{V{Type: "ubuntu", Pkg: "linux-libc-dev", InstalledVersion: "6.8.0-124.124", FixedVersion: "6.8.0-134.134"}, entity.ComponentOS, "6.8.0-124.124"},
		{V{Type: "rocky", Pkg: "openssl-libs", InstalledVersion: "1:3.0.7-27.el9", FixedVersion: "1:3.0.7-28.el9"}, entity.ComponentOS, "1:3.0.7-27.el9"},
		{V{Type: "gobinary", Target: "usr/bin/dockerd", Pkg: "stdlib"}, entity.ComponentBinary, "/usr/bin/dockerd"},
		{V{Type: "composer-vendor", Target: "PHP", PkgPath: "var/www/shop/vendor/composer/installed.json"}, entity.ComponentApp, "/var/www/shop"},
		{V{Type: "node-pkg", Target: "Node.js", PkgPath: "home/u/front/node_modules/@a/b/node_modules/c/package.json"}, entity.ComponentApp, "/home/u/front"},
		{V{Type: "python-pkg", Target: "Python", PkgPath: "usr/lib/python3/dist-packages/urllib3-2.0.7.dist-info/METADATA"}, entity.ComponentApp, "/usr/lib/python3"},
		{V{Type: "python-pkg", Target: "Python", PkgPath: "srv/api/.venv/lib/python3.12/site-packages/x-1.dist-info/METADATA"}, entity.ComponentApp, "/srv/api"},
		{V{Type: "python-pkg", Target: "Python", PkgPath: "home/u/.cache/uv/archive-v0/abc/aiohttp-3.14.3.dist-info/METADATA"}, entity.ComponentApp, "/home/u/.cache"},
		{V{Type: "jar", Target: "Java", PkgPath: "opt/api/app.jar"}, entity.ComponentApp, "/opt/api/app.jar"},
		{V{Type: "jar", Target: "Java", PkgPath: "home/u/.m2/repository/at/yawk/lz4/lz4-java-1.10.1.jar"}, entity.ComponentApp, "/home/u/.m2"},
		{V{Type: "composer", Target: "var/www/blog/composer.lock"}, entity.ComponentApp, "/var/www/blog"},
	}
	for _, c := range cases {
		kind, key := c.v.Component()
		assert.Equal(t, c.kind, kind, "%+v", c.v)
		assert.Equal(t, c.key, key, "%+v", c.v)
	}
}

func TestClientNamePattern(t *testing.T) {
	for _, ok := range []string{"client_a", "a", "acme-01"} {
		assert.True(t, entity.ClientNamePattern.MatchString(ok), ok)
	}
	for _, bad := range []string{"", "Client", "-a", "a b", strings.Repeat("a", 65)} {
		assert.False(t, entity.ClientNamePattern.MatchString(bad), bad)
	}
}

func TestMarkStale(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	cases := []struct {
		name             string
		h                entity.HostSummary
		scan, heartbeats bool
	}{
		{"fresh", entity.HostSummary{LastOKScanAt: ago(time.Hour), Host: entity.Host{LastHeartbeatAt: ago(time.Minute)}}, false, false},
		{"old scan", entity.HostSummary{LastOKScanAt: ago(49 * time.Hour), Host: entity.Host{LastHeartbeatAt: ago(time.Minute)}}, true, false},
		{"never scanned, old heartbeat", entity.HostSummary{Host: entity.Host{LastHeartbeatAt: ago(2 * time.Hour)}}, true, true},
		{"revoked is never stale", entity.HostSummary{Host: entity.Host{RevokedAt: ago(time.Hour)}}, false, false},
	}
	for _, c := range cases {
		c.h.MarkStale(now)
		assert.Equal(t, c.scan, c.h.StaleScan, c.name)
		assert.Equal(t, c.heartbeats, c.h.StaleHeartbeat, c.name)
	}
}

func TestBuildOverview(t *testing.T) {
	revoked := time.Now()
	clients := []entity.Client{{ID: 1, Name: "a"}, {ID: 2, Name: "b"}, {ID: 3, Name: "empty"}}
	hosts := []entity.HostSummary{
		{Host: entity.Host{ClientID: 1, Meta: entity.HostMeta{AutoUpdateEnabled: true}}, OpenCritical: 2, OpenHigh: 5, Accepted: 1},
		{Host: entity.Host{ClientID: 1, Meta: entity.HostMeta{RebootRequired: true}}, OpenHigh: 1, StaleScan: true},
		{Host: entity.Host{ClientID: 2, Meta: entity.HostMeta{AutoUpdateEnabled: true}}, OpenCritical: 1, FalsePositive: 3},
		{Host: entity.Host{ClientID: 2, RevokedAt: &revoked}, OpenCritical: 100}, // ignored
	}
	ov := entity.BuildOverview(clients, hosts)
	assert.Equal(t, entity.Totals{Clients: 3, Hosts: 3, OpenCritical: 3, OpenHigh: 6, Accepted: 1, FalsePositive: 3,
		StaleHosts: 1, RebootRequired: 1, AutoUpdateOff: 1}, ov.Totals)
	assert.Equal(t, []int{2, 2, 6}, []int{ov.Clients[0].Hosts, ov.Clients[0].OpenCritical, ov.Clients[0].OpenHigh})
	assert.Equal(t, "empty", ov.Clients[2].Name)
	assert.Zero(t, ov.Clients[2].Hosts)
}
