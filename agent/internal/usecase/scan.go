package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"netra-vuln/agent/internal/domain"
)

// scanGrace is the margin on top of Trivy's --timeout before the process is killed
// (default 30m + 10m = 40m).
const scanGrace = 10 * time.Minute

type Scan struct {
	Scanner Scanner
	Host    HostInspector
	Central Central
	Spool   Spool
	Cache   ScanConfigCache
	Flush   *Flush
	Now     func() time.Time
	Log     *slog.Logger
}

func (s *Scan) Run(ctx context.Context) error {
	if n, err := s.Flush.Run(ctx); err != nil {
		s.Log.Warn("flush spool before scan failed", "sent", n, "err", err)
	} else if n > 0 {
		s.Log.Info("flushed spool", "sent", n)
	}

	cfg := s.scanConfig(ctx)

	start := s.Now()
	scanCtx, cancel := context.WithTimeout(ctx, cfg.Timeout+scanGrace)
	findings, scanErr := s.Scanner.Scan(scanCtx, cfg)
	cancel()

	version, err := s.Scanner.Version(ctx)
	if err != nil {
		s.Log.Warn("read trivy version", "err", err)
	}

	r := domain.Report{
		Host:         s.Host.Inspect(ctx),
		Status:       domain.StatusOK,
		ScannedAt:    start,
		Duration:     s.Now().Sub(start),
		TrivyVersion: version,
		Findings:     findings,
	}
	if scanErr != nil {
		r.Status = domain.StatusError
		r.Error = domain.TruncateError(scanErr.Error())
		r.Findings = nil
		s.Log.Error("trivy scan failed", "err", scanErr)
	}
	s.Log.Info("scan finished", "status", r.Status, "findings", len(r.Findings), "duration", r.Duration)

	if err := s.Central.SendReport(ctx, r); err != nil {
		if errors.Is(err, ErrRejected) {
			return fmt.Errorf("send report: %w", err)
		}
		if serr := s.Spool.Save(r); serr != nil {
			return errors.Join(fmt.Errorf("send report: %w", err), fmt.Errorf("spool report: %w", serr))
		}
		return fmt.Errorf("send report (spooled): %w", err)
	}
	if scanErr != nil {
		return fmt.Errorf("scan failed (reported to central): %w", scanErr)
	}
	return nil
}

// scanConfig: config from central -> local cache -> default.
func (s *Scan) scanConfig(ctx context.Context) domain.ScanConfig {
	cfg, err := s.Central.FetchScanConfig(ctx)
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		if cerr := s.Cache.Save(cfg); cerr != nil {
			s.Log.Warn("cache scan config", "err", cerr)
		}
		return cfg
	}
	s.Log.Warn("fetch scan config failed, falling back", "err", err)

	cfg, err = s.Cache.Load()
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		s.Log.Info("using cached scan config")
		return cfg
	}
	s.Log.Info("using default scan config", "cache_err", err)
	return domain.DefaultScanConfig()
}
