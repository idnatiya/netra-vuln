package entity

import "time"

// TriageStatus is the admin's verdict on a finding. Only "open" findings count
// as actionable; the verdict survives re-scans.
type TriageStatus string

const (
	TriageOpen          TriageStatus = "open"
	TriageAccepted      TriageStatus = "accepted"
	TriageFalsePositive TriageStatus = "false_positive"

	MaxNoteLength = 2000
)

// Finding is a vulnerability stored per host, kept across scans.
type Finding struct {
	ID            int64  `gorm:"column:id;primaryKey"`
	HostID        int64  `gorm:"column:host_id"`
	FindingKey    []byte `gorm:"column:finding_key"`
	Vulnerability `gorm:"embedded"`
	ComponentKind ComponentKind `gorm:"column:component_kind"`
	Component     string        `gorm:"column:component"`
	FirstSeen     time.Time     `gorm:"column:first_seen"`
	LastSeen      time.Time     `gorm:"column:last_seen"`
	ResolvedAt    *time.Time    `gorm:"column:resolved_at"`
	Status        TriageStatus  `gorm:"column:status;default:open"`
	Note          *string       `gorm:"column:note"`
}

func (f *Finding) TableName() string { return "findings" }

// NewFinding stores a reported vulnerability as seen at `seen`.
func NewFinding(hostID int64, v Vulnerability, seen time.Time) Finding {
	kind, component := v.Component()
	return Finding{HostID: hostID, FindingKey: v.Key(), Vulnerability: v, ComponentKind: kind, Component: component,
		FirstSeen: seen, LastSeen: seen}
}
