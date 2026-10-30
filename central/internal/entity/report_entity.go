package entity

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/idnatiya/netra-vuln-agent/pkg/scanconfig"
)

type ScanStatus string

const (
	StatusOK    ScanStatus = "ok"
	StatusError ScanStatus = "error"
)

// Column sizes from db/migrations.
const (
	maxTarget       = 512
	maxPkgPath      = 1024
	maxType         = 64
	maxCVE          = 64
	maxPkg          = 255
	maxVersion      = 128
	maxFixedVersion = 255
	maxTitle        = 1024
	maxTrivyVersion = 64
	maxErrorMessage = 4096
	MaxFindings     = 200_000
)

// Vulnerability is one finding as reported by the agent.
type Vulnerability struct {
	Target           string `gorm:"column:target"`
	Type             string `gorm:"column:type"`
	CVE              string `gorm:"column:cve"`
	Pkg              string `gorm:"column:pkg"`
	PkgPath          string `gorm:"column:pkg_path"` // file the package was found in; empty for OS packages
	InstalledVersion string `gorm:"column:installed_version"`
	FixedVersion     string `gorm:"column:fixed_version"`
	Severity         string `gorm:"column:severity"`
	Title            string `gorm:"column:title"`
}

// Key identifies a finding on a host across scans. PkgPath is only mixed in
// when set, so keys of findings without one stay as before.
func (v Vulnerability) Key() []byte {
	h := sha256.New()
	parts := []string{v.CVE, v.Pkg, v.InstalledVersion, v.Target}
	if v.PkgPath != "" {
		parts = append(parts, v.PkgPath)
	}
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// Report is one scan result from an agent.
type Report struct {
	ClientName   string
	Hostname     string
	Meta         HostMeta
	TrivyVersion string
	ScannedAt    time.Time
	Duration     time.Duration
	Status       ScanStatus
	Error        string
	Findings     []Vulnerability
}

type Counts struct{ Total, Critical, High int }

func (r Report) Counts() Counts {
	c := Counts{Total: len(r.Findings)}
	for _, f := range r.Findings {
		switch f.Severity {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		}
	}
	return c
}

// Normalize makes a report storable instead of rejecting it for cosmetic issues:
// strings are cut to column sizes, unknown severities become UNKNOWN, duplicate
// findings are dropped, and error reports carry no findings.
func (r *Report) Normalize() {
	r.Meta.Normalize()
	r.TrivyVersion = truncate(r.TrivyVersion, maxTrivyVersion)
	r.Error = truncate(r.Error, maxErrorMessage)
	if r.Status == StatusError {
		r.Findings = nil
		return
	}
	seen := make(map[string]bool, len(r.Findings))
	out := r.Findings[:0]
	for _, f := range r.Findings {
		f.Target = truncate(f.Target, maxTarget)
		f.Type = truncate(f.Type, maxType)
		f.CVE = truncate(f.CVE, maxCVE)
		f.Pkg = truncate(f.Pkg, maxPkg)
		f.PkgPath = truncate(f.PkgPath, maxPkgPath)
		f.InstalledVersion = truncate(f.InstalledVersion, maxVersion)
		f.FixedVersion = truncate(f.FixedVersion, maxFixedVersion)
		f.Title = truncate(f.Title, maxTitle)
		if !slices.Contains(scanconfig.SeverityLevels, f.Severity) {
			f.Severity = "UNKNOWN"
		}
		if k := string(f.Key()); !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	r.Findings = out
}

// Validate rejects reports that cannot be stored meaningfully. Call after Normalize.
func (r Report) Validate(now time.Time) error {
	switch {
	case r.Status != StatusOK && r.Status != StatusError:
		return fmt.Errorf("status %q", r.Status)
	case r.ScannedAt.IsZero() || r.ScannedAt.After(now.Add(24*time.Hour)):
		return fmt.Errorf("scanned_at %s", r.ScannedAt)
	case len(r.Findings) > MaxFindings:
		return fmt.Errorf("%d findings (max %d)", len(r.Findings), MaxFindings)
	}
	for i, f := range r.Findings {
		if f.CVE == "" || f.Pkg == "" {
			return fmt.Errorf("finding %d has empty vulnerability_id or pkg_name", i)
		}
	}
	return nil
}

type Scan struct {
	ID              int64      `gorm:"column:id;primaryKey"`
	HostID          int64      `gorm:"column:host_id"`
	ScannedAt       time.Time  `gorm:"column:scanned_at"`
	Status          ScanStatus `gorm:"column:status"`
	ErrorMessage    *string    `gorm:"column:error_message"`
	DurationSeconds float64    `gorm:"column:duration_seconds"`
	Total           int        `gorm:"column:total"`
	Critical        int        `gorm:"column:critical"`
	High            int        `gorm:"column:high"`
	TrivyVersion    string     `gorm:"column:trivy_version"`
}

func (s *Scan) TableName() string { return "scans" }

// truncate cuts s to at most n runes (VARCHAR(n) counts characters).
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
