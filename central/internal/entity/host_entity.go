package entity

import "time"

// HostMeta is the host metadata reported by the agent on enroll, heartbeat, and report.
type HostMeta struct {
	OSFamily          string `gorm:"column:os_family"`
	OSName            string `gorm:"column:os_name"`
	OSVersion         string `gorm:"column:os_version"`
	Arch              string `gorm:"column:arch"`
	KernelRunning     string `gorm:"column:kernel_running"`
	AgentVersion      string `gorm:"column:agent_version"`
	RebootRequired    bool   `gorm:"column:reboot_required"`
	AutoUpdateEnabled bool   `gorm:"column:auto_update_enabled"`
}

// Normalize cuts metadata to the hosts column sizes.
func (m *HostMeta) Normalize() {
	m.OSFamily = truncate(m.OSFamily, 32)
	m.OSName = truncate(m.OSName, 128)
	m.OSVersion = truncate(m.OSVersion, 64)
	m.Arch = truncate(m.Arch, 16)
	m.KernelRunning = truncate(m.KernelRunning, 128)
	m.AgentVersion = truncate(m.AgentVersion, 64)
}

// Columns returns the metadata as an update map; a map (not a struct) so false
// booleans are written too.
func (m HostMeta) Columns() map[string]any {
	return map[string]any{
		"os_family": m.OSFamily, "os_name": m.OSName, "os_version": m.OSVersion, "arch": m.Arch,
		"kernel_running": m.KernelRunning, "agent_version": m.AgentVersion,
		"reboot_required": m.RebootRequired, "auto_update_enabled": m.AutoUpdateEnabled,
	}
}

type Host struct {
	ID              int64      `gorm:"column:id;primaryKey"`
	ClientID        int64      `gorm:"column:client_id"`
	Hostname        string     `gorm:"column:hostname"`
	HostTokenHash   []byte     `gorm:"column:host_token_hash"`
	Meta            HostMeta   `gorm:"embedded"`
	TrivyVersion    string     `gorm:"column:trivy_version"`
	LastHeartbeatAt *time.Time `gorm:"column:last_heartbeat_at"`
	LastScanAt      *time.Time `gorm:"column:last_scan_at"`
	LastScanStatus  ScanStatus `gorm:"column:last_scan_status;default:null"`
	CreatedAt       time.Time  `gorm:"column:created_at"`
	RevokedAt       *time.Time `gorm:"column:revoked_at"`
	Client          Client     `gorm:"foreignKey:ClientID;references:ID"`
}

func (h *Host) TableName() string { return "hosts" }

func (h *Host) Active() bool { return h.RevokedAt == nil }

// MaxHostname is the hosts.hostname column size.
const MaxHostname = 255

// NormalizeHostname cuts a hostname to the column size.
func NormalizeHostname(s string) string { return truncate(s, MaxHostname) }
