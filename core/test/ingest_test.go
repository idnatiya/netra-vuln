package test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngestLifecycle(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")

	// 1. New findings.
	ingest(t, h, "ok", cves("CVE-A", "CVE-B")...)
	f := findings(t, h.ID)
	require.Len(t, f, 2)
	assert.Nil(t, f["CVE-A"].ResolvedAt)
	t0 := f["CVE-A"].FirstSeen
	assert.Equal(t, t0, f["CVE-A"].LastSeen)

	// 2. A still present, B gone: B resolved, A keeps first_seen.
	ingest(t, h, "ok", cves("CVE-A")...)
	f = findings(t, h.ID)
	assert.Equal(t, t0, f["CVE-A"].FirstSeen)
	assert.True(t, f["CVE-A"].LastSeen.After(t0))
	assert.Nil(t, f["CVE-A"].ResolvedAt)
	require.NotNil(t, f["CVE-B"].ResolvedAt)
	assert.Equal(t, f["CVE-A"].LastSeen, *f["CVE-B"].ResolvedAt, "one timestamp per ingest")

	// 3. B reappears: reopened, first_seen kept.
	ingest(t, h, "ok", cves("CVE-A", "CVE-B")...)
	f = findings(t, h.ID)
	assert.Nil(t, f["CVE-B"].ResolvedAt)
	assert.Equal(t, t0, f["CVE-B"].FirstSeen)

	// 4. Error scan: recorded, nothing resolved.
	ingest(t, h, "error")
	f = findings(t, h.ID)
	assert.Nil(t, f["CVE-A"].ResolvedAt)
	assert.Nil(t, f["CVE-B"].ResolvedAt)

	assert.Equal(t, 4, count(t, "SELECT COUNT(*) FROM scans WHERE host_id = ?", h.ID))
	var first struct {
		Status      string
		Total, High int
	}
	db.Raw("SELECT status, total, high FROM scans WHERE host_id = ? ORDER BY id LIMIT 1", h.ID).Scan(&first)
	assert.Equal(t, "ok", first.Status)
	assert.Equal(t, 2, first.Total)
	assert.Equal(t, 2, first.High)
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM scans WHERE host_id = ? AND status = 'error' AND error_message = 'trivy failed'", h.ID))
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM hosts WHERE id = ? AND last_scan_status = 'error'", h.ID))
}

func TestIngestNormalizes(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	weird := vuln("CVE-3", "SUPER", "zlib")
	ingest(t, h, "ok", vuln("CVE-1", "HIGH", "openssl"), vuln("CVE-1", "HIGH", "openssl"), weird)
	assert.Equal(t, 2, count(t, "SELECT COUNT(*) FROM findings WHERE host_id = ?", h.ID), "duplicates dropped")
	assert.Equal(t, 1, count(t, "SELECT COUNT(*) FROM findings WHERE cve = 'CVE-3' AND severity = 'UNKNOWN'"))
}

func TestLargeUpsert(t *testing.T) {
	ClearAll(t)
	h := enrollHost(t, "client_a", "vm1")
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-%05d", i)
	}
	ingest(t, h, "ok", cves(ids...)...)
	ingest(t, h, "ok", cves(ids[:4000]...)...)
	assert.Equal(t, 4000, count(t, "SELECT COUNT(*) FROM findings WHERE host_id = ? AND resolved_at IS NULL", h.ID))
	assert.Equal(t, 5000, count(t, "SELECT COUNT(*) FROM findings WHERE host_id = ?", h.ID))
}
