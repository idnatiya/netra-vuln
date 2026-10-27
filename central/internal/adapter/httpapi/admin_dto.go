package httpapi

import (
	"encoding/json"
	"time"

	"netra-vuln/central/internal/domain"
)

// JSON shapes of the admin API (/api/admin/v1), consumed by the dashboard.
// These are separate from internal/wire, which is the agent contract.

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type meResponse struct {
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

type totalsDTO struct {
	Clients        int `json:"clients"`
	Hosts          int `json:"hosts"`
	OpenCritical   int `json:"open_critical"`
	OpenHigh       int `json:"open_high"`
	Accepted       int `json:"accepted"`
	FalsePositive  int `json:"false_positive"`
	StaleHosts     int `json:"stale_hosts"`
	RebootRequired int `json:"reboot_required"`
	AutoUpdateOff  int `json:"auto_update_off"`
}

type clientDTO struct {
	Name         string          `json:"name"`
	ScanConfig   json.RawMessage `json:"scan_config"` // null = agent defaults
	CreatedAt    time.Time       `json:"created_at"`
	Hosts        int             `json:"hosts"`
	OpenCritical int             `json:"open_critical"`
	OpenHigh     int             `json:"open_high"`
}

type overviewDTO struct {
	Totals  totalsDTO   `json:"totals"`
	Clients []clientDTO `json:"clients"`
}

type hostDTO struct {
	ID                int64      `json:"id"`
	Client            string     `json:"client"`
	Hostname          string     `json:"hostname"`
	OSFamily          string     `json:"os_family"`
	OSName            string     `json:"os_name"`
	OSVersion         string     `json:"os_version"`
	Arch              string     `json:"arch"`
	KernelRunning     string     `json:"kernel_running"`
	AgentVersion      string     `json:"agent_version"`
	TrivyVersion      string     `json:"trivy_version"`
	RebootRequired    bool       `json:"reboot_required"`
	AutoUpdateEnabled bool       `json:"auto_update_enabled"`
	LastHeartbeatAt   *time.Time `json:"last_heartbeat_at"`
	LastScanAt        *time.Time `json:"last_scan_at"`
	LastScanStatus    string     `json:"last_scan_status"`
	LastOKScanAt      *time.Time `json:"last_ok_scan_at"`
	CreatedAt         time.Time  `json:"created_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	OpenCritical      int        `json:"open_critical"`
	OpenHigh          int        `json:"open_high"`
	Accepted          int        `json:"accepted"`
	FalsePositive     int        `json:"false_positive"`
	StaleScan         bool       `json:"stale_scan"`
	StaleHeartbeat    bool       `json:"stale_heartbeat"`
}

type findingDTO struct {
	ID               int64      `json:"id"`
	HostID           int64      `json:"host_id"`
	Client           string     `json:"client"`
	Hostname         string     `json:"hostname"`
	Target           string     `json:"target"`
	Type             string     `json:"type"`
	CVE              string     `json:"cve"`
	Pkg              string     `json:"pkg"`
	InstalledVersion string     `json:"installed_version"`
	FixedVersion     string     `json:"fixed_version"`
	Severity         string     `json:"severity"`
	Title            string     `json:"title"`
	Status           string     `json:"status"`
	Note             string     `json:"note"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
	ResolvedAt       *time.Time `json:"resolved_at"`
}

type pageDTO[T any] struct {
	Items    []T `json:"items"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

type triageRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

type createClientRequest struct {
	Name string `json:"name"`
}

type createClientResponse struct {
	Name        string `json:"name"`
	EnrollToken string `json:"enroll_token"` // shown once
}

type trendDTO struct {
	Day      string `json:"day"` // YYYY-MM-DD (UTC)
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type cveAgeDTO struct {
	CVE       string    `json:"cve"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	FirstSeen time.Time `json:"first_seen"`
	Hosts     int       `json:"hosts"`
}

type countDTO struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

type distributionDTO struct {
	OS            []countDTO `json:"os"`
	AgentVersions []countDTO `json:"agent_versions"`
	TrivyVersions []countDTO `json:"trivy_versions"`
}

func toClientDTO(c domain.ClientRow) clientDTO {
	cfg := json.RawMessage("null")
	if c.ScanConfig != nil {
		cfg = c.ScanConfig
	}
	return clientDTO{Name: c.Name, ScanConfig: cfg, CreatedAt: c.CreatedAt,
		Hosts: c.Hosts, OpenCritical: c.OpenCritical, OpenHigh: c.OpenHigh}
}

func toClientDTOs(cs []domain.ClientRow) []clientDTO {
	out := make([]clientDTO, len(cs))
	for i, c := range cs {
		out[i] = toClientDTO(c)
	}
	return out
}

func toHostDTO(h domain.HostRow) hostDTO {
	return hostDTO{
		ID: h.ID, Client: h.ClientName, Hostname: h.Hostname,
		OSFamily: h.Meta.OSFamily, OSName: h.Meta.OSName, OSVersion: h.Meta.OSVersion,
		Arch: h.Meta.Arch, KernelRunning: h.Meta.KernelRunning, AgentVersion: h.Meta.AgentVersion,
		TrivyVersion: h.TrivyVersion, RebootRequired: h.Meta.RebootRequired,
		AutoUpdateEnabled: h.Meta.AutoUpdateEnabled, LastHeartbeatAt: h.LastHeartbeatAt,
		LastScanAt: h.LastScanAt, LastScanStatus: string(h.LastScanStatus), LastOKScanAt: h.LastOKScanAt,
		CreatedAt: h.CreatedAt, RevokedAt: h.RevokedAt,
		OpenCritical: h.OpenCritical, OpenHigh: h.OpenHigh, Accepted: h.Accepted, FalsePositive: h.FalsePositive,
		StaleScan: h.StaleScan, StaleHeartbeat: h.StaleHeartbeat,
	}
}

func toFindingDTO(f domain.FindingRow) findingDTO {
	return findingDTO{
		ID: f.ID, HostID: f.HostID, Client: f.ClientName, Hostname: f.Hostname,
		Target: f.Target, Type: f.Type, CVE: f.CVE, Pkg: f.Pkg,
		InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion,
		Severity: f.Severity, Title: f.Title, Status: string(f.Status), Note: f.Note,
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, ResolvedAt: f.ResolvedAt,
	}
}

func toCounts(cs []domain.Count) []countDTO {
	out := make([]countDTO, len(cs))
	for i, c := range cs {
		out[i] = countDTO{Key: c.Key, N: c.N}
	}
	return out
}

func mapSlice[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
