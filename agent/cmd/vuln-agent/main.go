// Command vuln-agent runs Trivy and sends the results to central.
// The agent is passive: it only sends data and reads declarative scan config.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netra-vuln/agent/internal/adapter/central"
	"netra-vuln/agent/internal/adapter/hostinfo"
	"netra-vuln/agent/internal/adapter/localconfig"
	"netra-vuln/agent/internal/adapter/spool"
	"netra-vuln/agent/internal/adapter/trivy"
	"netra-vuln/agent/internal/usecase"
)

var version = "dev" // -ldflags "-X main.version=..."

const (
	defaultConfig = "/etc/vuln-agent/config.yaml"
	stateDir      = "/var/lib/vuln-agent"
	trivyBin      = "/opt/vuln-agent/bin/trivy"
	spoolMax      = 5
	enrollEnv     = "VULN_AGENT_ENROLL_TOKEN"
)

const usage = `usage: vuln-agent <command> [-config path]

commands:
  scan       run one scan cycle and send the report
  heartbeat  send a heartbeat
  flush      resend spooled reports
  enroll     enroll this host (token from $VULN_AGENT_ENROLL_TOKEN or stdin) [-force]
  check      validate config, Trivy binary, and central connectivity
  version    print version
`

func main() { os.Exit(run(os.Args[1:], os.Stdin)) }

func run(args []string, stdin io.Reader) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Println(version)
		return 0
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfig, "config file")
	force := fs.Bool("force", false, "enroll: overwrite existing host token")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("cmd", cmd)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dispatch(ctx, log, cmd, *configPath, *force, stdin); err != nil {
		log.Error("failed", "err", err)
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, log *slog.Logger, cmd, configPath string, force bool, stdin io.Reader) error {
	cfgFile, warnings, err := localconfig.Load(configPath)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	cfg := cfgFile.Config

	httpClient, err := central.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return err
	}
	cen := &central.Client{
		BaseURL:   cfg.CentralURL,
		ClientID:  cfg.ClientID,
		Token:     cfgFile.HostToken(),
		UserAgent: "vuln-agent/" + version,
		HTTP:      httpClient,
	}
	host := &hostinfo.Linux{HostnameOverride: cfg.HostnameOverride, AgentVersion: version}
	scanner := &trivy.Runner{Bin: trivyBin, CacheDir: filepath.Join(stateDir, "cache"), TmpDir: stateDir}
	sp := &spool.Dir{Path: filepath.Join(stateDir, "spool"), Max: spoolMax}
	flush := &usecase.Flush{Spool: sp, Central: cen, Log: log}

	needsToken := cmd == "scan" || cmd == "heartbeat" || cmd == "flush"
	if needsToken && cfgFile.HostToken() == "" {
		return errors.New("host not enrolled: run `vuln-agent enroll` first")
	}

	switch cmd {
	case "scan":
		return (&usecase.Scan{
			Scanner: scanner, Host: host, Central: cen, Spool: sp,
			Cache: &localconfig.ScanConfigCache{Path: filepath.Join(stateDir, "scan-config.json")},
			Flush: flush, Now: time.Now, Log: log,
		}).Run(ctx)
	case "heartbeat":
		return (&usecase.Heartbeat{Host: host, Central: cen}).Run(ctx)
	case "flush":
		n, err := flush.Run(ctx)
		log.Info("flush done", "sent", n)
		return err
	case "enroll":
		tok, err := enrollToken(stdin)
		if err != nil {
			return err
		}
		if err := (&usecase.Enroll{Host: host, Central: cen, Creds: cfgFile}).Run(ctx, tok, force); err != nil {
			return err
		}
		log.Info("enrolled", "client_id", cfg.ClientID, "config", configPath)
		return nil
	case "check":
		return (&usecase.Check{Scanner: scanner, Central: cen, Creds: cfgFile, Log: log}).Run(ctx)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// enrollToken reads the token from env or the first line of stdin, never from CLI args.
func enrollToken(stdin io.Reader) (string, error) {
	if t := os.Getenv(enrollEnv); t != "" {
		return t, nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read enroll token from stdin: %w", err)
	}
	if t := strings.TrimSpace(line); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("enroll token required via $%s or stdin", enrollEnv)
}
