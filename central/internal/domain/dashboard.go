package domain

import (
	"fmt"
	"slices"
	"time"

	"netra-vuln/internal/scanconfig"
)

// TriageStatus is the admin's verdict on a finding. Only "open" findings count
// as actionable; the verdict survives re-scans.
type TriageStatus string

const (
	TriageOpen          TriageStatus = "open"
	TriageAccepted      TriageStatus = "accepted"
	TriageFalsePositive TriageStatus = "false_positive"

	MaxNoteLength = 2000
)

func (s TriageStatus) Valid() bool {
	return s == TriageOpen || s == TriageAccepted || s == TriageFalsePositive
}

// Thresholds after which a host needs attention.
const (
	StaleScanAfter      = 48 * time.Hour
	StaleHeartbeatAfter = time.Hour
)

// HostRow is a host with its open-finding counts for the dashboard.
type HostRow struct {
	Host
	LastOKScanAt   *time.Time
	OpenCritical   int
	OpenHigh       int
	Accepted       int
	FalsePositive  int
	StaleScan      bool // no successful scan within StaleScanAfter
	StaleHeartbeat bool // no heartbeat within StaleHeartbeatAfter
}

// MarkStale sets the stale flags for an active host.
func (h *HostRow) MarkStale(now time.Time) {
	if !h.Active() {
		h.StaleScan, h.StaleHeartbeat = false, false
		return
	}
	h.StaleScan = h.LastOKScanAt == nil || now.Sub(*h.LastOKScanAt) > StaleScanAfter
	h.StaleHeartbeat = h.LastHeartbeatAt == nil || now.Sub(*h.LastHeartbeatAt) > StaleHeartbeatAfter
}

type ClientRow struct {
	Client
	Hosts        int // active hosts
	OpenCritical int
	OpenHigh     int
}

type Totals struct {
	Clients        int
	Hosts          int // active
	OpenCritical   int
	OpenHigh       int
	Accepted       int
	FalsePositive  int
	StaleHosts     int
	RebootRequired int
	AutoUpdateOff  int
}

type Overview struct {
	Totals  Totals
	Clients []ClientRow
}

// BuildOverview aggregates active hosts per client. Clients without hosts are kept.
func BuildOverview(clients []Client, hosts []HostRow) Overview {
	byID := make(map[int64]*ClientRow, len(clients))
	ov := Overview{Clients: make([]ClientRow, len(clients))}
	for i, c := range clients {
		ov.Clients[i] = ClientRow{Client: c}
		byID[c.ID] = &ov.Clients[i]
	}
	ov.Totals.Clients = len(clients)
	for _, h := range hosts {
		if !h.Active() {
			continue
		}
		t := &ov.Totals
		t.Hosts++
		t.OpenCritical += h.OpenCritical
		t.OpenHigh += h.OpenHigh
		t.Accepted += h.Accepted
		t.FalsePositive += h.FalsePositive
		if h.StaleScan || h.StaleHeartbeat {
			t.StaleHosts++
		}
		if h.Meta.RebootRequired {
			t.RebootRequired++
		}
		if !h.Meta.AutoUpdateEnabled {
			t.AutoUpdateOff++
		}
		if c := byID[h.ClientID]; c != nil {
			c.Hosts++
			c.OpenCritical += h.OpenCritical
			c.OpenHigh += h.OpenHigh
		}
	}
	return ov
}

// FindingRow is a stored finding with its host and triage state.
type FindingRow struct {
	ID         int64
	HostID     int64
	ClientName string
	Hostname   string
	Finding
	Status     TriageStatus
	Note       string
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt *time.Time
}

// Finding list sort orders.
const (
	SortFirstSeen = "first_seen" // oldest first
	SortLastSeen  = "last_seen"  // newest first
	SortSeverity  = "severity"   // most severe first
)

type FindingFilter struct {
	Client          string
	HostID          int64
	Severity        string
	Status          TriageStatus // "" = any
	Query           string       // substring of CVE or package
	IncludeResolved bool
	Sort            string
	Page            int // 1-based
	PageSize        int
}

const (
	defaultPageSize = 50
	MaxPageSize     = 200
)

// Normalize applies defaults and rejects unknown enum values.
func (f *FindingFilter) Normalize() error {
	if f.Page < 1 {
		f.Page = 1
	}
	switch {
	case f.PageSize <= 0:
		f.PageSize = defaultPageSize
	case f.PageSize > MaxPageSize:
		f.PageSize = MaxPageSize
	}
	if f.Sort == "" {
		f.Sort = SortSeverity
	}
	if f.Sort != SortFirstSeen && f.Sort != SortLastSeen && f.Sort != SortSeverity {
		return fmt.Errorf("%w: sort %q", ErrInvalid, f.Sort)
	}
	if f.Severity != "" && !slices.Contains(scanconfig.SeverityLevels, f.Severity) {
		return fmt.Errorf("%w: severity %q", ErrInvalid, f.Severity)
	}
	if f.Status != "" && !f.Status.Valid() {
		return fmt.Errorf("%w: status %q", ErrInvalid, f.Status)
	}
	if len(f.Query) > 128 {
		return fmt.Errorf("%w: query too long", ErrInvalid)
	}
	return nil
}

type Page[T any] struct {
	Items []T
	Total int
}

// TrendPoint sums, per day, the last successful scan of each host that day.
type TrendPoint struct {
	Day      time.Time
	Critical int
	High     int
}

// CVEAge is an open CVE across hosts, oldest first.
type CVEAge struct {
	CVE       string
	Severity  string
	Title     string
	FirstSeen time.Time
	Hosts     int
}

type Count struct {
	Key string
	N   int
}

// Distribution counts active hosts by OS, agent version, and Trivy version.
type Distribution struct {
	OS            []Count
	AgentVersions []Count
	TrivyVersions []Count
}
