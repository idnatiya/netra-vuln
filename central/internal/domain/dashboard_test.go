package domain

import (
	"errors"
	"testing"
	"time"
)

func TestMarkStale(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	cases := []struct {
		name             string
		h                HostRow
		scan, heartbeats bool
	}{
		{"fresh", HostRow{LastOKScanAt: ago(time.Hour), Host: Host{LastHeartbeatAt: ago(time.Minute)}}, false, false},
		{"old scan", HostRow{LastOKScanAt: ago(49 * time.Hour), Host: Host{LastHeartbeatAt: ago(time.Minute)}}, true, false},
		{"never scanned, old heartbeat", HostRow{Host: Host{LastHeartbeatAt: ago(2 * time.Hour)}}, true, true},
		{"revoked is never stale", HostRow{Host: Host{RevokedAt: ago(time.Hour)}}, false, false},
	}
	for _, c := range cases {
		c.h.MarkStale(now)
		if c.h.StaleScan != c.scan || c.h.StaleHeartbeat != c.heartbeats {
			t.Errorf("%s: scan=%v heartbeat=%v", c.name, c.h.StaleScan, c.h.StaleHeartbeat)
		}
	}
}

func TestBuildOverview(t *testing.T) {
	revoked := time.Now()
	clients := []Client{{ID: 1, Name: "a"}, {ID: 2, Name: "b"}, {ID: 3, Name: "empty"}}
	hosts := []HostRow{
		{Host: Host{ClientID: 1, Meta: HostMeta{AutoUpdateEnabled: true}}, OpenCritical: 2, OpenHigh: 5, Accepted: 1},
		{Host: Host{ClientID: 1, Meta: HostMeta{RebootRequired: true}}, OpenHigh: 1, StaleScan: true},
		{Host: Host{ClientID: 2, Meta: HostMeta{AutoUpdateEnabled: true}}, OpenCritical: 1, FalsePositive: 3},
		{Host: Host{ClientID: 2, RevokedAt: &revoked}, OpenCritical: 100}, // ignored
	}
	ov := BuildOverview(clients, hosts)
	want := Totals{Clients: 3, Hosts: 3, OpenCritical: 3, OpenHigh: 6, Accepted: 1, FalsePositive: 3,
		StaleHosts: 1, RebootRequired: 1, AutoUpdateOff: 1}
	if ov.Totals != want {
		t.Fatalf("totals = %+v", ov.Totals)
	}
	if a := ov.Clients[0]; a.Hosts != 2 || a.OpenCritical != 2 || a.OpenHigh != 6 {
		t.Fatalf("client a = %+v", a)
	}
	if e := ov.Clients[2]; e.Name != "empty" || e.Hosts != 0 {
		t.Fatalf("empty client = %+v", e)
	}
}

func TestFindingFilterNormalize(t *testing.T) {
	f := FindingFilter{PageSize: 10_000}
	if err := f.Normalize(); err != nil || f.Page != 1 || f.PageSize != MaxPageSize || f.Sort != SortSeverity {
		t.Fatalf("defaults: %+v %v", f, err)
	}
	for _, bad := range []FindingFilter{{Sort: "id; DROP"}, {Severity: "SEVERE"}, {Status: "done"}} {
		if err := bad.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", bad)
		}
	}
}
