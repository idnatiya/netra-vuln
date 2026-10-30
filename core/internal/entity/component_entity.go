package entity

import (
	"path"
	"slices"
	"strings"
)

// ComponentKind says what a group of findings is: one upgrade action.
type ComponentKind string

const (
	ComponentOS     ComponentKind = "os"     // OS packages from the same source (same installed version)
	ComponentApp    ComponentKind = "app"    // language packages under one application folder
	ComponentBinary ComponentKind = "binary" // a compiled binary (Go, Rust)
)

// MaxComponent is the findings.component column size.
const MaxComponent = 512

// Trivy result types for OS package managers.
var osTypes = []string{
	"alma", "alpine", "amazon", "azurelinux", "bottlerocket", "cbl-mariner", "centos", "chainguard",
	"debian", "echo", "fedora", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "oracle",
	"photon", "redhat", "rocky", "sles", "suse", "ubuntu", "wolfi",
}

// Folders that hold an application's dependencies: the app is the folder above.
var depDirs = []string{"vendor", "node_modules", "site-packages", "dist-packages", ".venv", "venv", "WEB-INF", "BOOT-INF"}

// Package caches: everything below one is grouped as that cache.
var cacheDirs = []string{".m2", ".cache", ".npm", ".gradle", ".cargo"}

// Component groups a finding into the thing an admin upgrades.
//
// ponytail: OS packages group by installed version because Trivy does not
// report the source package per vulnerability; packages built from one source
// (all linux-* kernel pieces, openssl + libssl3) share it. The fixed version
// differs per CVE, so it is not part of the key. Unrelated packages with an
// identical version string would merge; switch to the source package name if
// Trivy ever emits it.
func (v Vulnerability) Component() (ComponentKind, string) {
	switch {
	case slices.Contains(osTypes, v.Type):
		return ComponentOS, truncate(v.InstalledVersion, MaxComponent)
	case v.Type == "gobinary" || v.Type == "rustbinary":
		return ComponentBinary, truncate("/"+v.Target, MaxComponent)
	case v.PkgPath != "":
		return ComponentApp, truncate(appRoot(v.PkgPath), MaxComponent)
	default: // lockfile scans: Target is the lockfile path
		return ComponentApp, truncate(appRoot(v.Target), MaxComponent)
	}
}

// appRoot maps a package file path (relative to /) to its application folder.
func appRoot(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		switch {
		case slices.Contains(depDirs, s):
			return "/" + path.Join(segs[:i]...)
		case slices.Contains(cacheDirs, s):
			return "/" + path.Join(segs[:i+1]...)
		case strings.HasSuffix(s, ".dist-info") || strings.HasSuffix(s, ".egg-info"):
			return "/" + path.Join(segs[:i]...)
		case strings.HasSuffix(s, ".jar") || strings.HasSuffix(s, ".war") || strings.HasSuffix(s, ".ear"):
			return "/" + path.Join(segs[:i+1]...)
		}
	}
	return "/" + path.Dir(strings.Trim(p, "/"))
}
