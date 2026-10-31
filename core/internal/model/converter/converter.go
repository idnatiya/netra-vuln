// Package converter maps entities to response models and wire payloads to entities.
package converter

import (
	"encoding/json"
	"time"

	"github.com/idnatiya/netra-vuln-agent/pkg/wire"

	"netra-vuln/core/internal/entity"
	"netra-vuln/core/internal/model"
)

func Map[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

// --- agent payloads (pkg/wire) to entities ---

func WireToMeta(h wire.Host) entity.HostMeta {
	return entity.HostMeta{
		OSFamily:          h.OSFamily,
		OSName:            h.OSName,
		OSVersion:         h.OSVersion,
		Arch:              h.Arch,
		KernelRunning:     h.KernelRunning,
		AgentVersion:      h.AgentVersion,
		RebootRequired:    h.RebootRequired,
		AutoUpdateEnabled: h.UnattendedUpgradesEnabled,
	}
}

func WireToReport(in *wire.Report) entity.Report {
	findings := make([]entity.Vulnerability, len(in.Findings))
	for i, f := range in.Findings {
		findings[i] = entity.Vulnerability{
			Target:           f.Target,
			Type:             f.Type,
			CVE:              f.VulnerabilityID,
			Pkg:              f.PkgName,
			PkgPath:          f.PkgPath,
			InstalledVersion: f.InstalledVersion,
			FixedVersion:     f.FixedVersion,
			Severity:         f.Severity,
			Title:            f.Title,
		}
	}
	return entity.Report{
		ClientName:   in.ClientID,
		Hostname:     in.Hostname,
		Meta:         WireToMeta(in.Host),
		TrivyVersion: in.TrivyVersion,
		ScannedAt:    in.ScannedAt,
		Duration:     time.Duration(in.ScanDurationSeconds * float64(time.Second)),
		Status:       entity.ScanStatus(in.Status),
		Error:        in.Error,
		Findings:     findings,
	}
}

// --- entities to admin responses ---

func ClientToResponse(c entity.ClientSummary) model.ClientResponse {
	cfg := json.RawMessage("null")
	if c.ScanConfig != nil {
		cfg = c.ScanConfig
	}
	return model.ClientResponse{Name: c.Name, ScanConfig: cfg, CreatedAt: c.CreatedAt,
		Hosts: c.Hosts, OpenCritical: c.OpenCritical, OpenHigh: c.OpenHigh}
}

func OverviewToResponse(ov entity.Overview) *model.OverviewResponse {
	t := ov.Totals
	return &model.OverviewResponse{
		Totals: model.TotalsResponse{Clients: t.Clients, Hosts: t.Hosts, OpenCritical: t.OpenCritical,
			OpenHigh: t.OpenHigh, Accepted: t.Accepted, FalsePositive: t.FalsePositive, StaleHosts: t.StaleHosts,
			RebootRequired: t.RebootRequired, AutoUpdateOff: t.AutoUpdateOff},
		Clients: Map(ov.Clients, ClientToResponse),
	}
}

func HostToResponse(h entity.HostSummary) model.HostResponse {
	return model.HostResponse{
		ID: h.ID, Client: h.ClientName, Hostname: h.Hostname,
		OSFamily: h.Meta.OSFamily, OSName: h.Meta.OSName, OSVersion: h.Meta.OSVersion,
		Arch: h.Meta.Arch, KernelRunning: h.Meta.KernelRunning, AgentVersion: h.Meta.AgentVersion,
		TrivyVersion: h.TrivyVersion, RebootRequired: h.Meta.RebootRequired,
		AutoUpdateEnabled: h.Meta.AutoUpdateEnabled, LastHeartbeatAt: h.LastHeartbeatAt,
		LastScanAt: h.LastScanAt, LastScanStatus: string(h.LastScanStatus), LastOKScanAt: h.LastOKScanAt,
		CreatedAt: h.CreatedAt, RevokedAt: h.RevokedAt,
		OpenCritical: h.OpenCritical, OpenHigh: h.OpenHigh, Accepted: h.Accepted, FalsePositive: h.FalsePositive,
		StaleScan: h.StaleScan, StaleHeartbeat: h.StaleHeartbeat,
		NewInLastScan: h.NewInLastScan, ResolvedInLastScan: h.ResolvedInLastScan, FirstScan: h.FirstScan,
	}
}

func FindingToResponse(f entity.FindingSummary) model.FindingResponse {
	note := ""
	if f.Note != nil {
		note = *f.Note
	}
	return model.FindingResponse{
		ID: f.ID, HostID: f.HostID, Client: f.ClientName, Hostname: f.Hostname,
		Target: f.Target, Type: f.Type, CVE: f.CVE, Pkg: f.Pkg, PkgPath: f.PkgPath,
		ComponentKind: string(f.ComponentKind), Component: f.Component,
		InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion,
		Severity: f.Severity, Title: f.Title, Status: string(f.Status), Note: note,
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, ResolvedAt: f.ResolvedAt,
	}
}

func ComponentToResponse(c entity.ComponentSummary) model.ComponentResponse {
	return model.ComponentResponse{
		HostID: c.HostID, Client: c.ClientName, Hostname: c.Hostname, Kind: string(c.Kind), Key: c.Key,
		Packages: c.Packages(), Types: c.Types(), PkgCount: c.PkgCount, Findings: c.Findings, CVEs: c.CVEs,
		Critical: c.Critical, High: c.High, FirstSeen: c.FirstSeen,
	}
}

func TrendToResponse(p entity.TrendPoint) model.TrendResponse {
	return model.TrendResponse{Day: p.Day.Format(time.DateOnly), Critical: p.Critical, High: p.High}
}

func CVEAgeToResponse(v entity.CVEAge) model.CVEAgeResponse {
	return model.CVEAgeResponse{CVE: v.CVE, Severity: v.Severity, Title: v.Title, FirstSeen: v.FirstSeen, Hosts: v.Hosts}
}

func DistributionToResponse(d entity.Distribution) *model.DistributionResponse {
	counts := func(cs []entity.Count) []model.KeyCountResponse {
		return Map(cs, func(c entity.Count) model.KeyCountResponse { return model.KeyCountResponse{Key: c.Key, N: c.N} })
	}
	return &model.DistributionResponse{OS: counts(d.OS), AgentVersions: counts(d.AgentVersions), TrivyVersions: counts(d.TrivyVersions)}
}

func SessionToResponse(s entity.AdminSession, current int64) model.SessionResponse {
	return model.SessionResponse{ID: s.ID, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, IP: s.IP,
		UserAgent: s.UserAgent, Current: s.ID == current}
}

func SessionToAuth(s *entity.AdminSession) *model.Auth {
	return &model.Auth{SessionID: s.ID, UserID: s.UserID, Username: s.User.Username, ExpiresAt: s.ExpiresAt}
}

func AdminUserToResponse(u entity.AdminUser) model.AdminUserResponse {
	return model.AdminUserResponse{Username: u.Username, CreatedAt: u.CreatedAt, DisabledAt: u.DisabledAt}
}

func McpTokenToResponse(t entity.McpToken) model.McpTokenResponse {
	return model.McpTokenResponse{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt}
}
