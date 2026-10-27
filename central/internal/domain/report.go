package domain

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"netra-vuln/internal/scanconfig"
)

type ScanStatus string

const (
	StatusOK    ScanStatus = "ok"
	StatusError ScanStatus = "error"
)

// Column sizes from migrations/0001_init.sql.
const (
	maxHostname     = 255
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

type Finding struct {
	Target           string
	Type             string
	CVE              string
	Pkg              string
	PkgPath          string // file the package was found in; empty for OS packages
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
}

// Key identifies a finding on a host across scans. PkgPath is only mixed in
// when set, so keys of findings without one stay as before.
func (f Finding) Key() []byte {
	h := sha256.New()
	parts := []string{f.CVE, f.Pkg, f.InstalledVersion, f.Target}
	if f.PkgPath != "" {
		parts = append(parts, f.PkgPath)
	}
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

type Report struct {
	ClientName   string
	Hostname     string
	Meta         HostMeta
	TrivyVersion string
	ScannedAt    time.Time
	Duration     time.Duration
	Status       ScanStatus
	Error        string
	Findings     []Finding
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
		return fmt.Errorf("%w: status %q", ErrInvalid, r.Status)
	case r.ScannedAt.IsZero() || r.ScannedAt.After(now.Add(24*time.Hour)):
		return fmt.Errorf("%w: scanned_at %s", ErrInvalid, r.ScannedAt)
	case len(r.Findings) > MaxFindings:
		return fmt.Errorf("%w: %d findings (max %d)", ErrInvalid, len(r.Findings), MaxFindings)
	}
	for i, f := range r.Findings {
		if f.CVE == "" || f.Pkg == "" {
			return fmt.Errorf("%w: finding %d has empty vulnerability_id or pkg_name", ErrInvalid, i)
		}
	}
	return nil
}

// truncate cuts s to at most n runes (VARCHAR(n) counts characters).
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
