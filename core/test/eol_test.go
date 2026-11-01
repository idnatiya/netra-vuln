package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
)

func TestEOLRules(t *testing.T) {
	cycles := []entity.EOLCycle{{Cycle: "8"}, {Cycle: "8.1", EOL: "2025-12-31"}, {Cycle: "8.3", EOL: "2027-12-31"}, {Cycle: "24.04", EOL: "false"}}
	c, ok := entity.MatchCycle("8.1.27", cycles)
	assert.True(t, ok)
	assert.Equal(t, "8.1", c.Cycle, "longest prefix at a dot")
	_, ok = entity.MatchCycle("8.10.1", cycles[1:])
	assert.False(t, ok, "8.1 must not match 8.10")
	c, _ = entity.MatchCycle("24.04", cycles)
	assert.Equal(t, "24.04", c.Cycle)

	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for eol, want := range map[string]entity.EOLStatus{
		"2025-12-31": entity.EOLStatusEOL, "2026-12-01": entity.EOLStatusSoon, "2027-12-31": entity.EOLStatusSupported,
		"true": entity.EOLStatusEOL, "false": entity.EOLStatusSupported, "soon-ish": entity.EOLStatusUnknown,
	} {
		assert.Equal(t, want, entity.EOLCycle{EOL: eol}.Status(now), eol)
	}

	os, ok := entity.OSSoftware(entity.HostMeta{OSName: "Rocky Linux", OSVersion: "9.4"})
	assert.True(t, ok)
	assert.Equal(t, entity.Software{Name: "rocky-linux", Version: "9.4"}, os)
}

// fakeEOL serves endoflife.date-shaped JSON: numeric cycles, bool and date eol.
func fakeEOL(t *testing.T) {
	t.Helper()
	data := map[string]string{
		"php":    `[{"cycle":"8.3","eol":"2027-12-31","latest":"8.3.13"},{"cycle":"7.4","eol":"2022-11-28","latest":"7.4.33"}]`,
		"ubuntu": `[{"cycle":"24.04","eol":"2029-04-25","latest":"24.04.1"}]`,
		"nodejs": `[{"cycle":20,"eol":"2026-12-15","latest":"20.18.0"}]`,
		"vue":    `[{"cycle":"2","eol":true,"latest":"2.7.16"}]`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := data[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	uc.EOL.BaseURL = srv.URL
}

func TestEOLSoftware(t *testing.T) {
	ClearAll(t)
	fakeEOL(t)
	assert.Error(t, uc.EOL.Refresh(context.Background()), "products without data are reported as failed")
	assert.Equal(t, 5, count(t, "SELECT COUNT(*) FROM eol_cycles"))

	h := enrollHost(t, "acme", "web-01")
	rep := report(h, "ok")
	rep.Software = []wire.Software{
		{Name: "php", Version: "7.4.33", Path: "/usr/bin/php"},
		{Name: "nodejs", Version: "20.11.1", Path: "/usr/bin/node"},
		{Name: "vue", Version: "2.7.16", Path: "/srv/shop"},
		{Name: "pm2", Version: "5.3.1", Path: "/usr/lib/node_modules/pm2"},
		{Name: "php", Version: "7.4.33", Path: "/usr/bin/php"}, // duplicate is dropped
		{Name: "", Version: "1"},                               // invalid is dropped
	}
	require.Equal(t, http.StatusNoContent, agentStatus(t, "POST", "/api/v1/report", h.Token, mustJSON(rep), true))

	cookie := adminSession(t)
	sw, _ := getData[[]model.SoftwareResponse](t, cookie, fmt.Sprintf("/hosts/%d/software", h.ID))
	status := map[string]string{}
	for _, s := range sw {
		status[s.Name] = s.Status + " " + s.Cycle
	}
	assert.Equal(t, map[string]string{"ubuntu": "supported 24.04", "php": "eol 7.4", "nodejs": "soon 20",
		"vue": "eol 2", "pm2": "unknown "}, status)

	hosts := hostsByName(t, cookie, "/hosts")
	assert.ElementsMatch(t, []string{"php 7.4", "vue 2"}, hosts["web-01"].EOL)
	assert.Equal(t, []string{"nodejs 20"}, hosts["web-01"].EOLSoon)

	// An older agent (no software) keeps the stored list; a failed scan too.
	ingest(t, h, "ok")
	ingest(t, h, "error")
	assert.Equal(t, 4, count(t, "SELECT COUNT(*) FROM host_software WHERE host_id = ?", h.ID))

	code, _ := adminDo(t, "GET", "/hosts/999999/software", "", cookie)
	assert.Equal(t, http.StatusNotFound, code)
}
