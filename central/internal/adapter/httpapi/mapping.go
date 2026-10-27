package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"netra-vuln/central/internal/domain"
	"netra-vuln/internal/wire"
)

// Requests are decoded leniently (unknown fields ignored) so newer agents keep
// working; responses use only wire types because the agent rejects unknown fields.

func decodeJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: decode JSON: %v", domain.ErrInvalid, err)
	}
	return nil
}

func toMeta(h wire.Host) domain.HostMeta {
	return domain.HostMeta{
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

func decodeEnroll(b []byte) (domain.EnrollRequest, error) {
	var in wire.EnrollRequest
	if err := decodeJSON(b, &in); err != nil {
		return domain.EnrollRequest{}, err
	}
	return domain.EnrollRequest{
		ClientName:  in.ClientID,
		EnrollToken: in.EnrollToken,
		Hostname:    in.Hostname,
		Meta:        toMeta(in.Host),
	}, nil
}

func enrollResponse(token string) wire.EnrollResponse { return wire.EnrollResponse{HostToken: token} }

func decodeHeartbeat(b []byte) (clientName, hostname string, meta domain.HostMeta, err error) {
	var in wire.Heartbeat
	if err := decodeJSON(b, &in); err != nil {
		return "", "", meta, err
	}
	return in.ClientID, in.Hostname, toMeta(in.Host), nil
}

func decodeReport(b []byte) (domain.Report, error) {
	var in wire.Report
	if err := decodeJSON(b, &in); err != nil {
		return domain.Report{}, err
	}
	findings := make([]domain.Finding, len(in.Findings))
	for i, f := range in.Findings {
		findings[i] = domain.Finding{
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
	return domain.Report{
		ClientName:   in.ClientID,
		Hostname:     in.Hostname,
		Meta:         toMeta(in.Host),
		TrivyVersion: in.TrivyVersion,
		ScannedAt:    in.ScannedAt,
		Duration:     time.Duration(in.ScanDurationSeconds * float64(time.Second)),
		Status:       domain.ScanStatus(in.Status),
		Error:        in.Error,
		Findings:     findings,
	}, nil
}

// encodeScanConfig re-decodes the stored overrides strictly into wire.ScanConfig,
// so only fields the agent accepts are ever sent.
func encodeScanConfig(raw []byte) (wire.ScanConfig, error) {
	var cfg wire.ScanConfig
	if len(raw) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("stored scan_config is invalid: %w", err)
	}
	return cfg, nil
}
