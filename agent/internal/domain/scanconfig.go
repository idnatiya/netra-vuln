package domain

import "netra-vuln/internal/scanconfig"

// ScanConfig is the only part of a scan that central is allowed to control.
// The rules are shared with central, see internal/scanconfig.
type ScanConfig = scanconfig.Config

func DefaultScanConfig() ScanConfig { return scanconfig.Default() }
