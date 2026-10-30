package model

import "time"

type HostResponse struct {
	ID                 int64      `json:"id"`
	Client             string     `json:"client"`
	Hostname           string     `json:"hostname"`
	OSFamily           string     `json:"os_family"`
	OSName             string     `json:"os_name"`
	OSVersion          string     `json:"os_version"`
	Arch               string     `json:"arch"`
	KernelRunning      string     `json:"kernel_running"`
	AgentVersion       string     `json:"agent_version"`
	TrivyVersion       string     `json:"trivy_version"`
	RebootRequired     bool       `json:"reboot_required"`
	AutoUpdateEnabled  bool       `json:"auto_update_enabled"`
	LastHeartbeatAt    *time.Time `json:"last_heartbeat_at"`
	LastScanAt         *time.Time `json:"last_scan_at"`
	LastScanStatus     string     `json:"last_scan_status"`
	LastOKScanAt       *time.Time `json:"last_ok_scan_at"`
	CreatedAt          time.Time  `json:"created_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
	OpenCritical       int        `json:"open_critical"`
	OpenHigh           int        `json:"open_high"`
	Accepted           int        `json:"accepted"`
	FalsePositive      int        `json:"false_positive"`
	StaleScan          bool       `json:"stale_scan"`
	StaleHeartbeat     bool       `json:"stale_heartbeat"`
	NewInLastScan      int        `json:"new_in_last_scan"`
	ResolvedInLastScan int        `json:"resolved_in_last_scan"`
	FirstScan          bool       `json:"first_scan"`
}

type SearchHostRequest struct {
	Client string `validate:"max=64"`
}

type RevokeHostRequest struct {
	ID int64 `validate:"required,min=1"`
}

// RevokeHostByNameRequest backs `central host revoke`; Client is needed only
// when the hostname exists in more than one client.
type RevokeHostByNameRequest struct {
	Hostname string `validate:"required,max=255"`
	Client   string `validate:"max=64"`
}
