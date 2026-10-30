package entity

import (
	"strings"
	"time"
)

// Read models filled by the dashboard queries (repository Raw scans).

// Thresholds after which a host needs attention.
const (
	StaleScanAfter      = 48 * time.Hour
	StaleHeartbeatAfter = time.Hour
)

// HostSummary is a host with its open-finding counts for the dashboard.
type HostSummary struct {
	Host
	ClientName     string     `gorm:"column:client_name"`
	LastOKScanAt   *time.Time `gorm:"column:last_ok_scan_at"`
	OpenCritical   int        `gorm:"column:open_critical"`
	OpenHigh       int        `gorm:"column:open_high"`
	Accepted       int        `gorm:"column:accepted"`
	FalsePositive  int        `gorm:"column:false_positive"`
	StaleScan      bool       `gorm:"-"` // no successful scan within StaleScanAfter
	StaleHeartbeat bool       `gorm:"-"` // no heartbeat within StaleHeartbeatAfter
	// Effect of the last scan, when it succeeded: findings it opened and resolved.
	// FirstScan means there was nothing to compare against.
	NewInLastScan      int  `gorm:"column:new_in_last_scan"`
	ResolvedInLastScan int  `gorm:"column:resolved_in_last_scan"`
	FirstScan          bool `gorm:"column:first_scan"`
}

// MarkStale sets the stale flags for an active host.
func (h *HostSummary) MarkStale(now time.Time) {
	if !h.Active() {
		h.StaleScan, h.StaleHeartbeat = false, false
		return
	}
	h.StaleScan = h.LastOKScanAt == nil || now.Sub(*h.LastOKScanAt) > StaleScanAfter
	h.StaleHeartbeat = h.LastHeartbeatAt == nil || now.Sub(*h.LastHeartbeatAt) > StaleHeartbeatAfter
}

type ClientSummary struct {
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
	Clients []ClientSummary
}

// BuildOverview aggregates active hosts per client. Clients without hosts are kept.
func BuildOverview(clients []Client, hosts []HostSummary) Overview {
	byID := make(map[int64]*ClientSummary, len(clients))
	ov := Overview{Clients: make([]ClientSummary, len(clients))}
	for i, c := range clients {
		ov.Clients[i] = ClientSummary{Client: c}
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

// FindingSummary is a stored finding with its host.
type FindingSummary struct {
	Finding
	ClientName string `gorm:"column:client_name"`
	Hostname   string `gorm:"column:hostname"`
}

// ComponentSummary sums the findings of one component on one host.
type ComponentSummary struct {
	HostID      int64         `gorm:"column:host_id"`
	ClientName  string        `gorm:"column:client_name"`
	Hostname    string        `gorm:"column:hostname"`
	Kind        ComponentKind `gorm:"column:component_kind"`
	Key         string        `gorm:"column:component"`
	PackageList string        `gorm:"column:packages"` // distinct package names, newline separated, capped
	TypeList    string        `gorm:"column:types"`    // distinct Trivy result types, newline separated
	PkgCount    int           `gorm:"column:pkg_count"`
	Findings    int           `gorm:"column:findings"`
	CVEs        int           `gorm:"column:cves"`
	Critical    int           `gorm:"column:critical"`
	High        int           `gorm:"column:high"`
	FirstSeen   time.Time     `gorm:"column:first_seen"` // oldest finding
}

func (c ComponentSummary) Packages() []string { return strings.Split(c.PackageList, "\n") }
func (c ComponentSummary) Types() []string    { return strings.Split(c.TypeList, "\n") }

// TrendPoint sums, per day, the last successful scan of each host that day.
type TrendPoint struct {
	Day      time.Time `gorm:"column:day"`
	Critical int       `gorm:"column:critical"`
	High     int       `gorm:"column:high"`
}

// CVEAge is an open CVE across hosts, oldest first.
type CVEAge struct {
	CVE       string    `gorm:"column:cve"`
	Severity  string    `gorm:"column:severity"`
	Title     string    `gorm:"column:title"`
	FirstSeen time.Time `gorm:"column:first_seen"`
	Hosts     int       `gorm:"column:hosts"`
}

type Count struct {
	Key string `gorm:"column:k"`
	N   int    `gorm:"column:n"`
}

// Distribution counts active hosts by OS, agent version, and Trivy version.
type Distribution struct {
	OS            []Count
	AgentVersions []Count
	TrivyVersions []Count
}
