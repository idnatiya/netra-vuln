// Command central is the central API server and its admin CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"netra-vuln/core/internal/config"
	"netra-vuln/core/internal/model"
)

var version = "dev" // -ldflags "-X main.version=..."

const usage = `usage: central <command>

environment (or config.json in ./ or ./core):
  CENTRAL_DB           SQLite database file (default central.db; the image uses /data/central.db)
  CENTRAL_BACKUP_DIR   serve: daily backup into this dir (empty = off), kept CENTRAL_BACKUP_KEEP_DAYS (14)
  CENTRAL_BACKUP_AT    serve: backup time, UTC HH:MM (default 02:30)
  CENTRAL_ADDR         listen address for serve (default :8080)
  CENTRAL_TRUST_PROXY  "true" behind a reverse proxy: client IP from X-Forwarded-For (private-network proxies)
  CENTRAL_LOG_LEVEL    logrus level 0-6 (default 4 = info)
  CENTRAL_PUBLIC_URL     URL VMs use to reach central; with CENTRAL_AGENT_VERSION enables /install.sh
  CENTRAL_AGENT_VERSION  agent release tag /install.sh downloads, e.g. v0.3.0
  CENTRAL_DASHBOARD_DIR  built dashboard SPA to serve (the image sets /srv/dashboard)
  CENTRAL_ADMIN_ALLOW_CIDRS  CIDRs allowed to reach the dashboard, admin API and /mcp (empty = all)

commands:
  serve                                    run the API server
  migrate                                  apply database migrations (serve and the CLI also do this)
  backup <file>                            write a consistent copy of the database (safe while serving)
  client enroll-token <name>               issue one single-use enroll token
  client create <name>                     create a client
  client set-config <name> <file.json|->   set scan overrides (wire.ScanConfig JSON)
  client set-config -clear <name>          remove scan overrides (agent defaults)
  client list
  host list [-client <name>]
  host revoke <hostname> [-client <name>]
  admin create <username>                  create a dashboard admin (password from stdin)
  admin passwd <username>                  set a new password (from stdin)
  admin list
  healthcheck                              exit 0 if the local server answers /healthz
  version
`

var errUsage = errors.New("usage")

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	if err := run(os.Args[1:], viperConfig, log); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		var fe *fiber.Error
		if errors.As(err, &fe) {
			err = errors.New(fe.Message)
		}
		log.WithError(err).Error("failed")
		os.Exit(1)
	}
}

func run(args []string, viperConfig *viper.Viper, log *logrus.Logger) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "healthcheck": // no database needed; used by the Docker healthcheck
		return healthcheck(viperConfig.GetString("web.addr"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db := config.NewDatabase(viperConfig, log)
	switch args[0] {
	case "migrate":
		return config.Migrate(db, log)
	case "backup":
		if len(args) != 2 {
			return errUsage
		}
		return config.Backup(db, args[1])
	}
	// Every other command needs the current schema; migrating is idempotent.
	if err := config.Migrate(db, log); err != nil {
		return err
	}
	validate := config.NewValidator(viperConfig)

	if args[0] == "serve" {
		app := config.NewFiber(viperConfig, log)
		viperConfig.Set("app.version", version)
		config.Bootstrap(&config.BootstrapConfig{DB: db, App: app, Log: log, Validate: validate, Config: viperConfig})
		go config.RunBackups(ctx, db, viperConfig, log)
		return serve(ctx, app, viperConfig.GetString("web.addr"), log)
	}

	uc := config.Bootstrap(&config.BootstrapConfig{DB: db, Log: log, Validate: validate, Config: viperConfig})
	switch cmd := args[0]; {
	case cmd == "client" && len(args) > 1:
		return clientCmd(ctx, uc, args[1], args[2:])
	case cmd == "host" && len(args) > 1:
		return hostCmd(ctx, uc, args[1], args[2:])
	case cmd == "admin" && len(args) > 1:
		return adminCmd(ctx, uc, args[1], args[2:])
	}
	return errUsage
}

func serve(ctx context.Context, app *fiber.App, addr string, log *logrus.Logger) error {
	errc := make(chan error, 1)
	go func() { errc <- app.Listen(addr, fiber.ListenConfig{DisableStartupMessage: true}) }()
	log.WithFields(logrus.Fields{"addr": addr, "version": version}).Info("central listening")
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

func clientCmd(ctx context.Context, uc *config.UseCases, sub string, args []string) error {
	fs := flag.NewFlagSet("client "+sub, flag.ContinueOnError)
	clear := fs.Bool("clear", false, "set-config: remove overrides")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return errUsage
	}
	switch {
	case sub == "create" && len(pos) == 1:
		res, err := uc.Client.Create(ctx, &model.CreateClientRequest{Name: pos[0]})
		if err != nil {
			return err
		}
		fmt.Printf("client %q created.\n", res.Name)
		return nil
	case sub == "enroll-token" && len(pos) == 1:
		res, err := uc.Client.IssueEnrollToken(ctx, &model.IssueEnrollTokenRequest{Name: pos[0]})
		if err != nil {
			return err
		}
		fmt.Println(res.EnrollToken)
		return nil
	case sub == "set-config" && *clear && len(pos) == 1:
		return uc.Client.SetScanConfig(ctx, &model.SetScanConfigRequest{Name: pos[0]})
	case sub == "set-config" && len(pos) == 2:
		cfg, err := readScanConfig(pos[1])
		if err != nil {
			return err
		}
		return uc.Client.SetScanConfig(ctx, &model.SetScanConfigRequest{Name: pos[0], Config: cfg})
	case sub == "list" && len(pos) == 0:
		clients, err := uc.Client.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSCAN_CONFIG\tCREATED")
		for _, c := range clients {
			cfg := "default"
			if string(c.ScanConfig) != "null" {
				cfg = string(c.ScanConfig)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, cfg, c.CreatedAt.Format(time.RFC3339))
		}
		return tw.Flush()
	}
	return errUsage
}

// readScanConfig reads overrides from a file or stdin ("-") and validates them.
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
	return wire.ParseScanConfig(b)
}

func hostCmd(ctx context.Context, uc *config.UseCases, sub string, args []string) error {
	fs := flag.NewFlagSet("host "+sub, flag.ContinueOnError)
	client := fs.String("client", "", "client name")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return errUsage
	}
	switch {
	case sub == "list" && len(pos) == 0:
		hosts, err := uc.Host.FindAll(ctx, &model.SearchHostRequest{Client: *client})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT\tHOSTNAME\tOS\tAGENT\tTRIVY\tLAST_HEARTBEAT\tLAST_SCAN\tSTATUS\tREVOKED")
		for _, h := range hosts {
			fmt.Fprintf(tw, "%s\t%s\t%s %s\t%s\t%s\t%s\t%s\t%s\t%s\n", h.Client.Name, h.Hostname,
				h.Meta.OSName, h.Meta.OSVersion, h.Meta.AgentVersion, h.TrivyVersion,
				ts(h.LastHeartbeatAt), ts(h.LastScanAt), dash(string(h.LastScanStatus)), ts(h.RevokedAt))
		}
		return tw.Flush()
	case sub == "revoke" && len(pos) == 1:
		h, err := uc.Host.RevokeByName(ctx, &model.RevokeHostByNameRequest{Hostname: pos[0], Client: *client})
		if err != nil {
			return err
		}
		fmt.Printf("revoked %s/%s; the agent must re-enroll to report again\n", h.Client.Name, h.Hostname)
		return nil
	}
	return errUsage
}

func adminCmd(ctx context.Context, uc *config.UseCases, sub string, args []string) error {
	switch {
	case sub == "create" && len(args) == 1:
		pw, err := readPassword()
		if err != nil {
			return err
		}
		if err := uc.AdminUser.Create(ctx, &model.CreateAdminRequest{Username: args[0], Password: pw}); err != nil {
			return err
		}
		fmt.Printf("admin %q created\n", args[0])
		return nil
	case sub == "passwd" && len(args) == 1:
		pw, err := readPassword()
		if err != nil {
			return err
		}
		if err := uc.AdminUser.SetPassword(ctx, &model.CreateAdminRequest{Username: args[0], Password: pw}); err != nil {
			return err
		}
		fmt.Printf("password for %q updated\n", args[0])
		return nil
	case sub == "list" && len(args) == 0:
		users, err := uc.AdminUser.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tCREATED\tDISABLED")
		for _, u := range users {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", u.Username, u.CreatedAt.Format(time.RFC3339), ts(u.DisabledAt))
		}
		return tw.Flush()
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

// readPassword prompts without echo on a terminal, or reads one line from a
// pipe (e.g. `docker compose exec -T central central admin create x < pw.txt`).
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "password (12-72 chars): ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 1024)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// healthcheck asks the local server for /healthz (the image has no curl).
func healthcheck(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	return nil
}
