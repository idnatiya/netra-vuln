package domain

import "time"

// HostMeta is the host metadata reported by the agent on enroll, heartbeat, and report.
type HostMeta struct {
	OSFamily          string
	OSName            string
	OSVersion         string
	Arch              string
	KernelRunning     string
	AgentVersion      string
	RebootRequired    bool
	AutoUpdateEnabled bool
}

type Host struct {
	ID              int64
	ClientID        int64
	ClientName      string
	Hostname        string
	Meta            HostMeta
	TrivyVersion    string
	LastHeartbeatAt *time.Time
	LastScanAt      *time.Time
	LastScanStatus  ScanStatus
	CreatedAt       time.Time
	RevokedAt       *time.Time
}

func (h Host) Active() bool { return h.RevokedAt == nil }

// EnrollRequest is a host asking to join a client with that client's enroll token.
type EnrollRequest struct {
	ClientName  string
	EnrollToken string
	Hostname    string
	Meta        HostMeta
}

func (r *EnrollRequest) Normalize() {
	r.Hostname = truncate(r.Hostname, maxHostname)
	r.Meta.Normalize()
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
