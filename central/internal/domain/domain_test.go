package domain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	f := Finding{CVE: "CVE-1", Pkg: "openssl", InstalledVersion: "1", Target: "t", Severity: "HIGH"}
	long := f
	long.CVE = "CVE-2"
	long.Title = strings.Repeat("é", 2000)
	weird := f
	weird.CVE = "CVE-3"
	weird.Severity = "SUPER"

	r := Report{Status: StatusOK, Findings: []Finding{f, f, long, weird}}
	r.Normalize()
	if len(r.Findings) != 3 {
		t.Fatalf("dedupe: %d findings", len(r.Findings))
	}
	if n := len([]rune(r.Findings[1].Title)); n != maxTitle {
		t.Fatalf("title runes = %d", n)
	}
	if r.Findings[2].Severity != "UNKNOWN" {
		t.Fatalf("severity = %q", r.Findings[2].Severity)
	}
	if c := r.Counts(); c != (Counts{Total: 3, High: 2}) {
		t.Fatalf("counts = %+v", c)
	}

	e := Report{Status: StatusError, Findings: []Finding{f}}
	e.Normalize()
	if e.Findings != nil {
		t.Fatal("error report kept findings")
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	ok := Report{Status: StatusOK, ScannedAt: now, Findings: []Finding{{CVE: "CVE-1", Pkg: "p"}}}
	if err := ok.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]Report{
		"status":   {Status: "done", ScannedAt: now},
		"zero ts":  {Status: StatusOK},
		"future":   {Status: StatusOK, ScannedAt: now.Add(48 * time.Hour)},
		"no cve":   {Status: StatusOK, ScannedAt: now, Findings: []Finding{{Pkg: "p"}}},
		"too many": {Status: StatusOK, ScannedAt: now, Findings: make([]Finding, MaxFindings+1)},
	} {
		if err := r.Validate(now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestFindingKey(t *testing.T) {
	a := Finding{CVE: "CVE-1", Pkg: "ab", InstalledVersion: "c", Target: "t"}
	b := Finding{CVE: "CVE-1", Pkg: "a", InstalledVersion: "bc", Target: "t"} // same concatenation
	if bytes.Equal(a.Key(), b.Key()) || len(a.Key()) != 32 {
		t.Fatal("keys must differ and be 32 bytes")
	}
	a2 := a
	a2.Title, a2.Severity, a2.FixedVersion = "other", "LOW", "9"
	if !bytes.Equal(a.Key(), a2.Key()) {
		t.Fatal("key must ignore non-identity fields")
	}
}

func TestValidateClientName(t *testing.T) {
	for _, ok := range []string{"client_a", "a", "acme-01"} {
		if err := ValidateClientName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Client", "-a", "a b", strings.Repeat("a", 65)} {
		if err := ValidateClientName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
