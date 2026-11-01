package entity

import (
	"strings"
	"time"
)

// Software is one installed product version on a host, replaced on every
// successful report (runtimes, databases, pm2, lockfile frameworks).
type Software struct {
	HostID  int64  `gorm:"column:host_id;primaryKey"`
	Name    string `gorm:"column:name;primaryKey"`
	Path    string `gorm:"column:path;primaryKey"`
	Version string `gorm:"column:version"`
}

func (Software) TableName() string { return "host_software" }

// EOLCycle is one release cycle of an endoflife.date product. EOL is a date
// (YYYY-MM-DD), "true" (ended, no date) or "false" (no end planned).
type EOLCycle struct {
	Product   string    `gorm:"column:product;primaryKey"`
	Cycle     string    `gorm:"column:cycle;primaryKey"`
	EOL       string    `gorm:"column:eol"`
	Latest    string    `gorm:"column:latest"`
	FetchedAt time.Time `gorm:"column:fetched_at"`
}

func (EOLCycle) TableName() string { return "eol_cycles" }

// EOLProducts maps reported software names to endoflife.date products.
// Software without a product (pm2) is listed with status unknown.
var EOLProducts = map[string]string{
	"php": "php", "nodejs": "nodejs", "nginx": "nginx", "apache": "apache-http-server",
	"mysql": "mysql", "mariadb": "mariadb", "redis": "redis", "postgresql": "postgresql",
	"laravel": "laravel", "symfony": "symfony", "nuxt": "nuxt", "vue": "vue",
	"next": "nextjs", "react": "react", "angular": "angular",
}

// osProducts maps /etc/os-release NAME prefixes to endoflife.date products.
var osProducts = []struct{ prefix, product string }{
	{"Ubuntu", "ubuntu"}, {"Debian", "debian"}, {"AlmaLinux", "almalinux"}, {"Rocky", "rocky-linux"},
	{"CentOS", "centos"}, {"Red Hat", "rhel"},
}

// OSSoftware is the host's OS as a Software row (name = endoflife product), or false if unknown.
func OSSoftware(m HostMeta) (Software, bool) {
	for _, o := range osProducts {
		if strings.HasPrefix(m.OSName, o.prefix) && m.OSVersion != "" {
			return Software{Name: o.product, Version: m.OSVersion}, true
		}
	}
	return Software{}, false
}

// AllEOLProducts lists every product to fetch from endoflife.date.
func AllEOLProducts() []string {
	var out []string
	for _, p := range EOLProducts {
		out = append(out, p)
	}
	for _, o := range osProducts {
		out = append(out, o.product)
	}
	return out
}

// Product returns the endoflife.date product of a software name (OS rows are already products).
func Product(name string) string {
	if p, ok := EOLProducts[name]; ok {
		return p
	}
	for _, o := range osProducts {
		if o.product == name {
			return name
		}
	}
	return ""
}

type EOLStatus string

const (
	EOLStatusEOL       EOLStatus = "eol"
	EOLStatusSoon      EOLStatus = "soon" // within EOLSoonWithin
	EOLStatusSupported EOLStatus = "supported"
	EOLStatusUnknown   EOLStatus = "unknown" // no product, no data yet, or no matching cycle
)

const EOLSoonWithin = 90 * 24 * time.Hour

// MatchCycle picks the longest cycle that equals the version or prefixes it at
// a dot ("8.1" for "8.1.27", "20" for "20.11.1", "24.04" for "24.04").
func MatchCycle(version string, cycles []EOLCycle) (EOLCycle, bool) {
	var best EOLCycle
	found := false
	for _, c := range cycles {
		if (version == c.Cycle || strings.HasPrefix(version, c.Cycle+".")) && len(c.Cycle) > len(best.Cycle) {
			best, found = c, true
		}
	}
	return best, found
}

// Status of a cycle at now.
func (c EOLCycle) Status(now time.Time) EOLStatus {
	switch c.EOL {
	case "true":
		return EOLStatusEOL
	case "false", "":
		return EOLStatusSupported
	}
	d, err := time.Parse(time.DateOnly, c.EOL)
	switch {
	case err != nil:
		return EOLStatusUnknown
	case !now.Before(d):
		return EOLStatusEOL
	case d.Sub(now) <= EOLSoonWithin:
		return EOLStatusSoon
	}
	return EOLStatusSupported
}

// SoftwareEOL is a software row with its matched cycle and status.
type SoftwareEOL struct {
	Software
	Product string
	Cycle   EOLCycle // zero when unknown
	Status  EOLStatus
}

// Label is the short name used in host issues, e.g. "php 7.4".
func (s SoftwareEOL) Label() string {
	if s.Cycle.Cycle != "" {
		return s.Name + " " + s.Cycle.Cycle
	}
	return s.Name + " " + s.Version
}

// EvaluateEOL matches each software row against the cycles of its product.
func EvaluateEOL(software []Software, cycles map[string][]EOLCycle, now time.Time) []SoftwareEOL {
	out := make([]SoftwareEOL, len(software))
	for i, s := range software {
		e := SoftwareEOL{Software: s, Product: Product(s.Name), Status: EOLStatusUnknown}
		if c, ok := MatchCycle(s.Version, cycles[e.Product]); ok {
			e.Cycle, e.Status = c, c.Status(now)
		}
		out[i] = e
	}
	return out
}
