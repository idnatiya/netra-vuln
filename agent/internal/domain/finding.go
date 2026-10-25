// Package domain holds agent entities and pure business rules (stdlib only).
package domain

// Finding is a single slimmed-down vulnerability from a scan.
type Finding struct {
	Target           string
	Type             string
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
}
