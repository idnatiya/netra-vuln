package model

import "time"

type TrendRequest struct {
	Client string `validate:"max=64"`
	HostID int64  `validate:"min=0"`
	Days   int    `validate:"min=1,max=365"`
}

type TrendResponse struct {
	Day      string `json:"day"` // YYYY-MM-DD (UTC)
	Critical int    `json:"critical"`
	High     int    `json:"high"`
}

type OldestCVERequest struct {
	Client string `validate:"max=64"`
	Limit  int    `validate:"min=1,max=100"`
}

type CVEAgeResponse struct {
	CVE       string    `json:"cve"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	FirstSeen time.Time `json:"first_seen"`
	Hosts     int       `json:"hosts"`
}

type KeyCountResponse struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

type DistributionResponse struct {
	OS            []KeyCountResponse `json:"os"`
	AgentVersions []KeyCountResponse `json:"agent_versions"`
	TrivyVersions []KeyCountResponse `json:"trivy_versions"`
}
