// Command central is the central API server and its admin CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/term"

	"netra-vuln/central/internal/adapter/httpapi"
	"netra-vuln/central/internal/adapter/mysql"
	"netra-vuln/central/internal/usecase"
	"github.com/idnatiya/netra-vuln-agent/pkg/wire"
	"netra-vuln/migrations"
)

var version = "dev" // -ldflags "-X main.version=..."

const usage = `usage: central <command>

environment:
  CENTRAL_DSN          MySQL DSN, e.g. user:pass@tcp(mysql:3306)/vuln   (required)
  CENTRAL_ADDR         listen address for serve (default :8080)
  CENTRAL_TRUST_PROXY  "true" behind Caddy: client IP from X-Forwarded-For (private-network proxies)

commands:
  serve                                    run the API server
  migrate                                  apply database migrations
  client create <name>                     create a client, print its enroll token once
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
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "healthcheck": // no DSN needed; used by the Docker healthcheck
		return healthcheck()
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
	case cmd == "admin" && len(args) > 1:
		return adminCmd(ctx, &usecase.AdminAuth{Store: store, Now: time.Now}, args[1], args[2:])
	}
	return errUsage
}

func serve(ctx context.Context, store *mysql.Store, log *slog.Logger) error {
	addr := os.Getenv("CENTRAL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := httpapi.New(
		&usecase.Agent{Store: store, Now: time.Now},
		&usecase.Enroll{Store: store, Now: time.Now},
		log, httpapi.Options{Limits: httpapi.DefaultLimits(), TrustProxy: os.Getenv("CENTRAL_TRUST_PROXY") == "true"})
	srv.MountAdmin(
		&usecase.AdminAuth{Store: store, Now: time.Now},
		&usecase.Dashboard{Queries: store, Store: store, Admin: &usecase.Admin{Store: store, Now: time.Now}, Now: time.Now})
	app := srv.App()

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

func adminCmd(ctx context.Context, auth *usecase.AdminAuth, sub string, args []string) error {
	switch {
	case sub == "create" && len(args) == 1:
		pw, err := readPassword()
		if err != nil {
			return err
		}
		if err := auth.CreateAdmin(ctx, args[0], pw); err != nil {
			return err
		}
		fmt.Printf("admin %q created\n", args[0])
		return nil
	case sub == "passwd" && len(args) == 1:
		pw, err := readPassword()
		if err != nil {
			return err
		}
		if err := auth.SetPassword(ctx, args[0], pw); err != nil {
			return err
		}
		fmt.Printf("password for %q updated\n", args[0])
		return nil
	case sub == "list" && len(args) == 0:
		users, err := auth.ListAdmins(ctx)
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
func healthcheck() error {
	addr := os.Getenv("CENTRAL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
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
