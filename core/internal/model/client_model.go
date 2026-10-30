package model

import (
	"encoding/json"
	"time"
)

type ClientResponse struct {
	Name         string          `json:"name"`
	ScanConfig   json.RawMessage `json:"scan_config"` // null = agent defaults
	CreatedAt    time.Time       `json:"created_at"`
	Hosts        int             `json:"hosts"`
	OpenCritical int             `json:"open_critical"`
	OpenHigh     int             `json:"open_high"`
}

type CreateClientRequest struct {
	Name string `json:"name" validate:"required,clientname"`
}

type CreateClientResponse struct {
	Name string `json:"name"`
}

// SetScanConfigRequest carries already-validated wire.ScanConfig JSON; nil clears it.
type SetScanConfigRequest struct {
	Name   string `validate:"required,max=64"`
	Config []byte
}

type TotalsResponse struct {
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

type OverviewRequest struct {
	Client string `validate:"max=64"`
}

type OverviewResponse struct {
	Totals  TotalsResponse   `json:"totals"`
	Clients []ClientResponse `json:"clients"`
}

type IssueEnrollTokenRequest struct {
	Name string `validate:"required,max=64"`
}

type EnrollTokenResponse struct {
	EnrollToken string `json:"enroll_token"` // shown once
}

// InstallInfoResponse tells the dashboard how to build the one-line install command.
type InstallInfoResponse struct {
	Enabled      bool   `json:"enabled"`
	PublicURL    string `json:"public_url"`
	AgentVersion string `json:"agent_version"`
}
