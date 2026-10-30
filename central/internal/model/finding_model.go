package model

import "time"

type FindingResponse struct {
	ID               int64      `json:"id"`
	HostID           int64      `json:"host_id"`
	Client           string     `json:"client"`
	Hostname         string     `json:"hostname"`
	Target           string     `json:"target"`
	Type             string     `json:"type"`
	CVE              string     `json:"cve"`
	Pkg              string     `json:"pkg"`
	PkgPath          string     `json:"pkg_path"`
	ComponentKind    string     `json:"component_kind"`
	Component        string     `json:"component"`
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

// Finding list sort orders.
const (
	SortFirstSeen = "first_seen" // oldest first
	SortLastSeen  = "last_seen"  // newest first
	SortSeverity  = "severity"   // most severe first

	DefaultPageSize = 50
	MaxPageSize     = 200
)

// SearchFindingRequest filters /findings and /components (paging and sort
// apply to /findings only).
type SearchFindingRequest struct {
	Client          string `validate:"max=64"`
	HostID          int64  `validate:"min=0"`
	Severity        string `validate:"omitempty,oneof=UNKNOWN LOW MEDIUM HIGH CRITICAL"`
	Status          string `validate:"omitempty,oneof=open accepted false_positive"`
	Query           string `validate:"max=128"` // substring of CVE or package
	ComponentKind   string `validate:"omitempty,oneof=os app binary"`
	Component       string `validate:"max=512"`
	IncludeResolved bool
	Sort            string `validate:"omitempty,oneof=first_seen last_seen severity"`
	Page            int    `validate:"min=0"` // 1-based; 0 = 1
	Size            int    `validate:"min=0"` // 0 = DefaultPageSize; capped at MaxPageSize
}

type TriageFindingRequest struct {
	ID     int64  `json:"-" validate:"required,min=1"`
	Status string `json:"status" validate:"required,oneof=open accepted false_positive"`
	Note   string `json:"note" validate:"max=2000"`
}

type ComponentResponse struct {
	HostID    int64     `json:"host_id"`
	Client    string    `json:"client"`
	Hostname  string    `json:"hostname"`
	Kind      string    `json:"kind"`
	Key       string    `json:"key"`
	Packages  []string  `json:"packages"`
	Types     []string  `json:"types"`
	PkgCount  int       `json:"pkg_count"`
	Findings  int       `json:"findings"`
	CVEs      int       `json:"cves"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	FirstSeen time.Time `json:"first_seen"`
}

type TriageComponentRequest struct {
	HostID int64  `json:"host_id" validate:"required,min=1"`
	Kind   string `json:"kind" validate:"required,oneof=os app binary"`
	Key    string `json:"key" validate:"max=512"`
	Status string `json:"status" validate:"required,oneof=open accepted false_positive"`
	Note   string `json:"note" validate:"max=2000"`
}

type TriageComponentResponse struct {
	Updated int `json:"updated"`
}
