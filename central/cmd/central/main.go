// Command central is the central API server and its admin CLI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gofiber/fiber/v3"

	"netra-vuln/central/internal/adapter/httpapi"
	"netra-vuln/central/internal/adapter/mysql"
	"netra-vuln/central/internal/usecase"
	"netra-vuln/internal/wire"
	"netra-vuln/migrations"
)

var version = "dev" // -ldflags "-X main.version=..."

const usage = `usage: central <command>

environment:
  CENTRAL_DSN    MySQL DSN, e.g. user:pass@tcp(mysql:3306)/vuln   (required)
  CENTRAL_ADDR   listen address for serve (default :8080)

commands:
  serve                                    run the API server
  migrate                                  apply database migrations
  client create <name>                     create a client, print its enroll token once
  client set-config <name> <file.json|->   set scan overrides (wire.ScanConfig JSON)
  client set-config -clear <name>          remove scan overrides (agent defaults)
  client list
  host list [-client <name>]
  host revoke <hostname> [-client <name>]
  version
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		log.Error("failed", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return errUsage
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	dsn := os.Getenv("CENTRAL_DSN")
	if dsn == "" {
		return errors.New("CENTRAL_DSN is not set")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if args[0] == "migrate" {
		db, err := mysql.Open(dsn, true)
		if err != nil {
			return err
		}
		defer db.Close()
		return mysql.Migrate(ctx, db, migrations.FS, log)
	}

	db, err := mysql.Open(dsn, false)
	if err != nil {
		return err
	}
	defer db.Close()
	store := mysql.New(db)
	admin := &usecase.Admin{Store: store, Now: time.Now}

	switch cmd := args[0]; {
	case cmd == "serve":
		return serve(ctx, store, log)
	case cmd == "client" && len(args) > 1:
		return clientCmd(ctx, admin, args[1], args[2:])
	case cmd == "host" && len(args) > 1:
		return hostCmd(ctx, admin, args[1], args[2:])
	}
	return errUsage
}

func serve(ctx context.Context, store usecase.Store, log *slog.Logger) error {
	addr := os.Getenv("CENTRAL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	app := httpapi.New(
		&usecase.Agent{Store: store, Now: time.Now},
		&usecase.Enroll{Store: store, Now: time.Now},
		log, httpapi.DefaultLimits()).App()

	errc := make(chan error, 1)
	go func() { errc <- app.Listen(addr, fiber.ListenConfig{DisableStartupMessage: true}) }()
	log.Info("central listening", "addr", addr, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return app.ShutdownWithContext(shutdownCtx)
}

func clientCmd(ctx context.Context, admin *usecase.Admin, sub string, args []string) error {
	fs := flag.NewFlagSet("client "+sub, flag.ContinueOnError)
	clear := fs.Bool("clear", false, "set-config: remove overrides")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return errUsage
	}
	switch {
	case sub == "create" && len(pos) == 1:
		token, err := admin.CreateClient(ctx, pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("client %q created.\nenroll token (shown once, store it in Ansible Vault):\n%s\n", pos[0], token)
		return nil
	case sub == "set-config" && *clear && len(pos) == 1:
		return admin.SetScanConfig(ctx, pos[0], nil)
	case sub == "set-config" && len(pos) == 2:
		cfg, err := readScanConfig(pos[1])
		if err != nil {
			return err
		}
		return admin.SetScanConfig(ctx, pos[0], cfg)
	case sub == "list" && len(pos) == 0:
		clients, err := admin.ListClients(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSCAN_CONFIG\tCREATED")
		for _, c := range clients {
			cfg := "default"
			if c.ScanConfig != nil {
				cfg = string(c.ScanConfig)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, cfg, c.CreatedAt.Format(time.RFC3339))
		}
		return tw.Flush()
	}
	return errUsage
}

// readScanConfig reads, strictly decodes, and validates overrides, returning
// canonical JSON so only allowed fields are ever stored.
func readScanConfig(path string) ([]byte, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var cfg wire.ScanConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("scan config: %w (allowed: severity, ignore_unfixed, skip_dirs, timeout)", err)
	}
	if _, err := cfg.Resolve(); err != nil {
		return nil, fmt.Errorf("scan config: %w", err)
	}
	return json.Marshal(cfg)
}

func hostCmd(ctx context.Context, admin *usecase.Admin, sub string, args []string) error {
	fs := flag.NewFlagSet("host "+sub, flag.ContinueOnError)
	client := fs.String("client", "", "client name")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return errUsage
	}
	switch {
	case sub == "list" && len(pos) == 0:
		hosts, err := admin.ListHosts(ctx, *client)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT\tHOSTNAME\tOS\tAGENT\tTRIVY\tLAST_HEARTBEAT\tLAST_SCAN\tSTATUS\tREVOKED")
		for _, h := range hosts {
			fmt.Fprintf(tw, "%s\t%s\t%s %s\t%s\t%s\t%s\t%s\t%s\t%s\n", h.ClientName, h.Hostname,
				h.Meta.OSName, h.Meta.OSVersion, h.Meta.AgentVersion, h.TrivyVersion,
				ts(h.LastHeartbeatAt), ts(h.LastScanAt), dash(string(h.LastScanStatus)), ts(h.RevokedAt))
		}
		return tw.Flush()
	case sub == "revoke" && len(pos) == 1:
		h, err := admin.RevokeHost(ctx, pos[0], *client)
		if err != nil {
			return err
		}
		fmt.Printf("revoked %s/%s; the agent must re-enroll to report again\n", h.ClientName, h.Hostname)
		return nil
	}
	return errUsage
}

// parseInterspersed allows flags before and after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
