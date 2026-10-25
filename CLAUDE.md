# Project: Vuln Agent & Central

## Language
Everything in this repo is written in **English**: code, identifiers, comments, log messages, error strings, docs, commit messages, and config examples.

## Context
I manage 26 Linux VMs belonging to several different clients, spread across various hosting providers. Distros are mixed: Ubuntu/Debian and the RHEL family (AlmaLinux/Rocky/CentOS). I need a centralized system to monitor package vulnerabilities across all of these VMs.

Build the system using an **agent + central** model:
- **Agent**: a small non-AI program (daemon) installed on each VM. Its only job is to run Trivy, slim down the results, and send them to central.
- **Central**: receiving API + MySQL + Grafana for dashboards.

Work in phases (see "Phases"). At the end of each phase, stop and show the results before continuing. If a design decision is ambiguous, ask first.

## Mandatory Principles
1. **Passive agent**: the agent ONLY sends data and fetches declarative (read-only) config. The agent MUST NOT have any feature to run commands, scripts, or auto-updates from central in any form.
2. **Push only**: all communication is initiated by the agent to central. Central never connects to a VM. Transport is HTTPS by default; plain HTTP is allowed only over an already-encrypted network (e.g. Tailscale), and the agent logs a warning when it is used.
3. **VMs never touch MySQL directly.** Only the central API accesses the database.
4. **Multi-tenant**: all data is bound to a `client`. A token belonging to client A must not be able to send or read data for client B.
5. **Simple and maintainable**: avoid unnecessary dependencies. Keep scope small.

## Stack
- Language: **Go** (latest stable) for agent and central
- Central HTTP: **Fiber v3** (fasthttp); agent uses stdlib `net/http` client
- Agent: static binary (`CGO_ENABLED=0`), targets `linux/amd64` and `linux/arm64`
- Scanner: **Trivy binary** invoked via `os/exec` (DO NOT import Trivy as a library). Trivy version is pinned in the build config.
- Database: **MySQL 8**
- Dashboard: **Grafana** with a provisioned MySQL datasource
- Agent packaging: **nfpm** or **GoReleaser** producing `.deb` and `.rpm`, plus a `.tar.gz` tarball + `install.sh`
- Central deployment: **Docker Compose** (central API + MySQL + Grafana + TLS reverse proxy, e.g. Caddy)
- Agent deployment: **Ansible role** (`deploy/ansible/roles/vuln_agent`)
- CI: **GitLab CI** (`.gitlab-ci.yml`)

## Repo Layout (monorepo)
```
/agent        # agent Go code
/central      # central API Go code
/deploy
  /central    # docker-compose.yml, Caddyfile, .env.example
  /grafana    # datasource provisioning + dashboard JSON
  /ansible    # role "vuln_agent", dev inventory, example per-client inventory
  /dev        # fakecentral: dev stand-in for central (logs + saves agent payloads)
/packaging    # nfpm config, systemd units, postinstall/preremove scripts, config.example.yaml
/migrations   # SQL migrations
/docs         # README, architecture, install guide
.gitlab-ci.yml
```

## Agent Specification

### Code structure (clean architecture)
Single Go module at the repo root (`go.mod`, module `netra-vuln`). The agent's only external dependency is `gopkg.in/yaml.v3`.
```
agent/
  cmd/vuln-agent/       # composition root: parse subcommand, wire adapters -> usecases
  internal/
    domain/             # entities + pure business rules (Finding, Report, HostInfo, ScanConfig), stdlib only
    usecase/            # scan/heartbeat/flush/enroll/check orchestration; ports (interfaces) defined in ports.go
    adapter/
      trivy/            # Scanner: exec Trivy + streaming parser
      hostinfo/         # Linux HostInspector
      central/          # HTTP client to central; dto.go maps domain <-> internal/wire
      spool/            # filesystem spool
      localconfig/      # config.yaml + ScanConfig cache
```
Dependency rule: `domain` <- `usecase` <- `adapter` <- `cmd`. Domain knows nothing about JSON/HTTP/exec. Interfaces are defined on the consumer side (`usecase`).

### Shared packages (root `internal/`, used by agent and central)
- `internal/wire`: the JSON contract (only JSON-tagged contract types). Central decodes requests leniently (ignores unknown fields, so newer agents keep working); the agent decodes responses strictly, so central must never add response fields.
- `internal/scanconfig`: `Config`, `Default()`, `Validate()`; the agent's `domain.ScanConfig` is an alias. Central validates `client set-config` with the same rules.

### File locations
- Agent binary: `/opt/vuln-agent/bin/vuln-agent`
- Trivy binary: `/opt/vuln-agent/bin/trivy`
- Config: `/etc/vuln-agent/config.yaml` (mode 600, owner root)
- Spool: `/var/lib/vuln-agent/spool/`
- Trivy cache: `/var/lib/vuln-agent/cache/`

### Local config (`config.yaml`)
See `packaging/config.example.yaml`.
```yaml
central_url: https://<central.domain>   # http:// allowed over Tailscale, with a warning
client_id: <client_a>
token: <per-host token>
hostname_override: ""        # optional; defaults to the OS hostname
ca_file: ""                  # optional, for a custom CA
```

### CLI subcommands
- `vuln-agent scan`: run one scan cycle + send (invoked by a systemd timer)
- `vuln-agent heartbeat`: send a heartbeat
- `vuln-agent flush`: resend spooled reports
- `vuln-agent enroll [--force]`: read `central_url` + `client_id` from config, read the enroll token from env `VULN_AGENT_ENROLL_TOKEN` or stdin (NEVER via CLI args, so it does not leak in `ps`), call `POST /api/v1/enroll`, and write `host_token` into `config.yaml` atomically (mode 600). Refuse if a token is already set, unless `--force`.
- `vuln-agent version`
- `vuln-agent check`: validate config, connectivity to central, and presence of the Trivy binary

### `scan` flow
1. Fetch scan config from `GET /api/v1/config` (read-only). On failure, use the last locally cached config, or the default if none exists.
2. Run Trivy with a `context` timeout (default 40 minutes), at low priority (`nice`/`ionice` equivalent), with default arguments:
   ```
   rootfs /
   --scanners vuln
   --list-all-pkgs=false
   --ignore-unfixed
   --severity HIGH,CRITICAL
   --timeout 30m
   --cache-dir /var/lib/vuln-agent/cache
   --skip-dirs /proc,/sys,/dev,/run,/tmp,/snap,/var/lib/snapd,/var/lib/docker,/var/lib/containerd,/mnt,/media,/var/cache,/root/.cache,/home/*/.cache,/home/*/.local/share/pnpm,/usr/share/doc
   --format json -q --output <temp file>
   ```
   `severity`, `ignore_unfixed`, `skip_dirs`, and `timeout` can be overridden by config from central, but the agent ONLY accepts those fields. Reject any other field.
3. Decode the output with `json.NewDecoder` (streaming) into a slim struct containing only:
   `Target, Type, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title`.
4. Add host metadata:
   `hostname, os_family, os_name, os_version, arch, kernel_running, uptime_seconds, reboot_required (check /var/run/reboot-required or needs-restarting -r), unattended_upgrades_enabled (or dnf-automatic on RHEL), agent_version, trivy_version, scanned_at, scan_duration_seconds`.
5. Send the payload gzipped to `POST /api/v1/report`.
6. If sending fails, save it to the spool (keep at most the 5 newest files, delete older ones). On the next scan or flush, send spooled reports first.
7. If Trivy fails, still send a report with status `error` and its error message (truncated to at most 4KB), so central knows the scan failed.

### Heartbeat
`POST /api/v1/heartbeat` with compact host metadata. Scheduled every 15 minutes.

### systemd
- `vuln-agent-scan.service` + `vuln-agent-scan.timer` (daily, `RandomizedDelaySec=2h` so the 26 VMs do not scan simultaneously, `Persistent=true`)
- `vuln-agent-heartbeat.service` + `.timer` (every 15 minutes)
- Resource limits: `CPUQuota=100%`, `MemoryMax=1G`, `Nice=19`, `IOSchedulingClass=idle`

### Logging
Log to stdout/stderr (into journald), structured format (`log/slog`). NEVER print the token in logs.

## Central Specification

### Endpoints (HTTPS, or HTTP over Tailscale; auth `Authorization: Bearer <token>`)
- `POST /api/v1/enroll`: body `{client_id, enroll_token, hostname, ...metadata}`, returns `host_token`. `enroll_token` is a per-client token (created by an admin). `host_token` is unique per host and revocable. Re-enroll of an **active** hostname → 409; after `central host revoke`, enroll issues a new token for the same host row (history kept).
- `POST /api/v1/heartbeat`
- `GET  /api/v1/config`: returns the client's overrides (`clients.scan_config`, allowed fields only), or `{}` for agent defaults
- `POST /api/v1/report`: accepts gzip, body size limit (e.g. 20MB after decompression), schema validation
- `GET  /healthz`

Admin CLI (subcommands of the central binary, not public endpoints):
- `central client create <name>` → generates an enroll token (printed once)
- `central client set-config <name> <file.json|->` / `central client set-config -clear <name>` / `central client list`
- `central host list [-client <name>]`
- `central host revoke <hostname> [-client <name>]`
- `central migrate`, `central serve` (env `CENTRAL_DSN`, `CENTRAL_ADDR`)

Status codes matter to the agent: 400/413/422 = permanent reject (agent drops the report); 401/403/409/429/5xx = retried or spooled.

Code layout mirrors the agent: `central/cmd/central` + `central/internal/{domain,usecase,adapter/{mysql,httpapi}}`; `httpapi` is the only package that imports Fiber. Read report bodies with `BodyRaw()` + explicit gunzip, not `c.Body()` (on decode errors it returns the error text as the body). A raw body over `BodyLimit` is cut off by fasthttp (connection reset), so the agent spools and retries it.

### Security
- Tokens are stored hashed (e.g. SHA-256), not in plaintext
- Validate that a host can only write to its own client
- Simple per-token rate limiting
- Request size limits, read/write timeouts
- TLS is handled by the reverse proxy (Caddy); for Tailscale-only deployments central may listen on plain HTTP bound to the tailnet interface only

### MySQL schema (as migrations)
- `clients` (id, name unique, scan_config JSON NULL, created_at)
- `enroll_tokens` (id, client_id, token_hash, created_at, revoked_at)
- `hosts` (id, client_id, hostname, host_token_hash, os_family, os_name, os_version, arch, kernel_running, agent_version, trivy_version, reboot_required, auto_update_enabled, last_heartbeat_at, last_scan_at, last_scan_status, created_at, revoked_at; UNIQUE(client_id, hostname))
- `scans` (id, host_id, scanned_at, status, error_message, duration_seconds, total, critical, high, trivy_version)
- `findings` (id, host_id, target, type, cve, pkg, installed_version, fixed_version, severity, title, first_seen, last_seen, resolved_at NULL, status ENUM('open','accepted','false_positive') default 'open', note; UNIQUE(host_id, finding_key) where finding_key = SHA-256(cve, pkg, installed_version, target), because a 5-column UNIQUE exceeds InnoDB's 3072-byte key limit with utf8mb4)
- Indexes needed for dashboard queries

### Report ingest logic (in a single transaction)
1. Insert a `scans` row.
2. For each finding: upsert into `findings`, update `last_seen`, and set `resolved_at = NULL` if it was previously resolved.
3. Findings for that host with `resolved_at IS NULL` that are not in this scan → set `resolved_at = NOW()`.
4. If the scan status is `error`, DO NOT perform steps 2–3 (do not mark findings resolved just because a scan failed).
5. Update `hosts.last_scan_at` and `last_scan_status`.

## Grafana (provisioned)
MySQL datasource with a **read-only** user. Dashboard with `client` and `host` variables:
1. Count of open CRITICAL/HIGH per client and per host
2. List of open findings (table), filterable by severity/pkg/cve
3. Hosts with no successful scan > 48 hours, or no heartbeat > 1 hour
4. Hosts with `reboot_required = true` or auto-update disabled
5. Finding count trend over time (from the `scans` table)
6. Oldest open CVEs (by `first_seen`)
7. Summary of OS distribution, agent versions, and Trivy versions

## Deployment
- `deploy/central/docker-compose.yml`: central API, MySQL (persistent volume), Grafana, Caddy (automatic HTTPS). Include `.env.example`, healthchecks, and an example daily MySQL backup.
- `deploy/ansible/roles/vuln_agent`:
  - Detect `ansible_architecture` (x86_64/aarch64) and later `ansible_os_family` for `.deb`/`.rpm`
  - `vuln_agent_install_method: binary` (now: copy `dist/vuln-agent-linux-<arch>` + pinned Trivy release with checksum) → `package` once Phase 4 ships packages; tarball fallback for unknown distros
  - Template `config.yaml` from inventory vars, compared by content and preserving the existing host token (enroll rewrites the file)
  - Enroll only when no token (or `vuln_agent_force_enroll`), enroll token from Ansible Vault, `no_log`
  - Run `vuln-agent check`; enable timers once packaging provides the systemd units
  - Example inventory grouped per client with different SSH user/port/key per group and `ProxyJump`
- Dev loop (laptop + sample VM over Tailscale): `make central-dev` (MySQL on 127.0.0.1:3317 via `deploy/dev/mysql.compose.yml`, central on the laptop's tailnet IP) or `make fakecentral`, then `make deploy-dev` / `make scan-dev`; admin CLI via `make central ARGS="..."`.
- Tests: `make test` (unit, MySQL tests skip), `make test-integration` (starts MySQL, sets `TEST_MYSQL_DSN`).
- Manual install without Ansible: `.deb`/`.rpm` package or tarball + `install.sh`, fill in `config.yaml`, `vuln-agent enroll`, `vuln-agent check`.

## Packaging & CI
- nfpm/GoReleaser produces: `.deb`, `.rpm`, `.tar.gz` (amd64 + arm64)
- Download the pinned Trivy binary at build time, verify its checksum, bundle it into the package
- Postinstall script: create directories, set permissions, `systemctl daemon-reload`, enable timers (but do not start a scan if the config is not filled in yet)
- Preremove script: stop and disable timers
- GitLab CI: lint, test, build, package, and publish artifacts to the GitLab Package Registry; central image to the GitLab Container Registry

## Testing
- Unit tests for the Trivy parser with JSON fixtures (including large files and empty output)
- Unit tests for ingest logic (new finding, still present, resolved, reappeared, scan error)
- Central integration tests with MySQL (testcontainers or compose)
- Test that a client A token is rejected when sending for a client B host

## Documentation (`/docs`)
- README: short architecture (text diagram), how to deploy central, how to enroll a new VM, how to revoke a host
- Security notes: what the agent reads, what data is sent, data retention
- Troubleshooting: scan timeouts, large output size, SELinux on RHEL, CentOS 7/8 EOL

## Phases
1. **Phase 1**: agent (scan, slim, send, spool, heartbeat, enroll, check) + tests
2. **Phase 2**: DB schema + migrations, central API (enroll, heartbeat, config, report) + tests, following the contract in `internal/wire`
3. **Phase 3**: central Docker Compose + Grafana provisioning + dashboard
4. **Phase 4**: packaging (deb/rpm/tarball) + systemd + GitLab CI
5. **Phase 5**: finalize the Ansible role (package install + timers) + documentation

## Out of Scope (do not build)
- Remote command execution in the agent
- Agent auto-update from central
- Custom web UI (Grafana is enough)
- Secret, misconfig, or license scanning (vuln only for now)
- AI/LLM integration
