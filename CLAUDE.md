# Project: Vuln Agent & Central

## Language
Everything in this repo is written in **English**: code, identifiers, comments, log messages, error strings, docs, commit messages, and config examples.

## Context
I manage 26 Linux VMs belonging to several different clients, spread across various hosting providers. Distros are mixed: Ubuntu/Debian and the RHEL family (AlmaLinux/Rocky/CentOS). I need a centralized system to monitor package vulnerabilities across all of these VMs.

Build the system using an **agent + central** model:
- **Agent** (separate repo, see "Agent"): a small non-AI program installed on each VM. It runs Trivy, slims down the results, and sends them to central (it can also run standalone without central).
- **Central** (this repo): receiving API + SQLite + an admin web dashboard.

Work in phases (see "Phases"). At the end of each phase, stop and show the results before continuing. If a design decision is ambiguous, ask first.

## Mandatory Principles
1. **Passive agent**: the agent ONLY sends data and fetches declarative (read-only) config. The agent MUST NOT have any feature to run commands, scripts, or auto-updates from central in any form.
2. **Push only**: all communication is initiated by the agent to central. Central never connects to a VM. Transport is HTTPS by default; plain HTTP is allowed only over an already-encrypted network (e.g. Tailscale), and the agent logs a warning when it is used.
3. **VMs never touch the database directly.** Only the central API accesses it.
4. **Multi-tenant**: all data is bound to a `client`. A token belonging to client A must not be able to send or read data for client B.
5. **Simple and maintainable**: avoid unnecessary dependencies. Keep scope small.

## Stack
- Language: **Go** (latest stable)
- Central HTTP: **Fiber v3** (fasthttp)
- Database: **SQLite** (one file, WAL; pure-Go driver, no CGO) — ample for a few dozen VMs and keeps central at tens of MB of RAM
- Central libraries (after [khannedy/golang-clean-architecture](https://github.com/khannedy/golang-clean-architecture)): GORM (`github.com/glebarez/sqlite`), Viper, Logrus (JSON), go-playground/validator, testify; migrations are embedded SQL files applied by a small runner in `config/migrate.go` (golang-migrate's SQLite driver would register a second `sqlite` driver)
- Dashboard: **Vue 3 + Vite + TypeScript + Tailwind v4 + shadcn-vue** SPA in `/dashboard` (admin only), built into the central image and served by central, talking to its `/api/admin/v1`
- Central deployment: **Docker Compose** (one container: central API with the dashboard SPA, the SQLite file and its daily backups on a volume); TLS comes from the operator's own reverse proxy
- CI: **GitLab CI** (`.gitlab-ci.yml`)

## Repo Layout
Go module `netra-vuln` (requires `github.com/idnatiya/netra-vuln-agent` for the contract).
```
/core         # central API Go code (cmd, db/migrations, internal, test)
Dockerfile, docker-compose.yml, .env.example   # production stack
/dashboard    # admin SPA (Vue + shadcn-vue, clean architecture)
/docs         # README, architecture, install guide
.gitlab-ci.yml
```

## Agent (separate repo)
The agent lives in its own repo/module: `github.com/idnatiya/netra-vuln-agent` (local checkout `../netra-vuln-agent`; its `CLAUDE.md` is the agent spec). It runs standalone (reports kept on the VM) or, with `central_url` set, pushes to this central.

- The JSON contract is owned by the agent module: `github.com/idnatiya/netra-vuln-agent/pkg/wire` (request/response types) and `.../pkg/scanconfig` (`Config`, `Default()`, `Validate()`; central validates `client set-config` with the same rules). Central decodes requests leniently (ignores unknown fields, so newer agents keep working); the agent decodes responses strictly, so central must never add response fields.
- Central pins the agent module by tag in `go.mod`; after a contract change, tag the agent repo and `go get github.com/idnatiya/netra-vuln-agent@vX.Y.Z`. For local work across both repos use an untracked `go.work` (`use . ../netra-vuln-agent`).
- Agent status codes: 400/413/422 = permanent reject (agent drops the report); 401/403/409/429/5xx = retried or spooled.
- Packaging, systemd units, the Ansible role (`vuln_agent`), and `fakecentral` are in the agent repo.

## Central Specification

### Endpoints (HTTPS, or HTTP over Tailscale; auth `Authorization: Bearer <token>`)
- `POST /api/v1/enroll`: body `{client_id, enroll_token, hostname, ...metadata}`, returns `host_token`. `enroll_token` is issued by an admin for one successful enrollment and is bound to a client. `host_token` is unique per host and revocable. Re-enroll of an **active** hostname → 409; after `central host revoke`, enroll issues a new token for the same host row (history kept).
- `POST /api/v1/heartbeat`
- `GET  /api/v1/config`: returns the client's overrides (`clients.scan_config`, allowed fields only), or `{}` for agent defaults
- `POST /api/v1/report`: accepts gzip, body size limit (e.g. 20MB after decompression), schema validation
- `GET  /healthz`

Admin CLI (subcommands of the central binary, not public endpoints):
- `central client create <name>` creates a client; `central client enroll-token <name>` issues a single-use token (printed once)
- `central client set-config <name> <file.json|->` / `central client set-config -clear <name>` / `central client list`
- `central host list [-client <name>]`
- `central host revoke <hostname> [-client <name>]`
- `central migrate`, `central serve` (env `CENTRAL_DSN`, `CENTRAL_ADDR`, `CENTRAL_TRUST_PROXY`, `CENTRAL_LOG_LEVEL`; or `config.json` in `./` or `./core`, env wins)

Status codes matter to the agent: 400/413/422 = permanent reject (agent drops the report); 401/403/409/429/5xx = retried or spooled.

Code layout follows khannedy/golang-clean-architecture under `core/`:
```
cmd/central/main.go      # CLI subcommands; serve = NewViper > NewLogger > NewDatabase > NewValidator > NewFiber > Bootstrap
config.json              # dev defaults (env overrides)
db/migrations/           # <timestamp>_<name>.up.sql, embedded, applied in order (schema_migrations)
internal/
  entity/                # GORM table structs + pure rules (finding key, component, report normalize/validate, stale, overview)
  model/ model/converter # admin request (validate tags) / response types, WebResponse; entity -> model
  repository/            # Repository[T] + per-table repositories (GORM; complex reads via Raw)
  usecase/               # one use case per resource; returns *fiber.Error, owns transactions
  delivery/http/         # controllers; middleware/ (host auth, session, same-origin, rate limit, body); route/route.go
  config/                # viper, logrus, gorm (DSN), validator, fiber (error handler), migrate, app.go (Bootstrap)
test/                    # black-box tests through app.Test against a temp SQLite file
```
Admin API (`/api/admin/v1/*`) responses use `model.WebResponse{data, paging, errors}`; agent API (`/api/v1/*`) responses are `pkg/wire` types as-is and errors plain text. Read report bodies with `BodyRaw()` + explicit gunzip, not `c.Body()` (on decode errors it returns the error text as the body). A raw body over `BodyLimit` is cut off by fasthttp (connection reset), so the agent spools and retries it.

### Security
- Admin `DELETE /api/admin/v1/hosts/:id` permanently deletes a revoked host and all its scans and findings in one transaction. Active hosts return 409; unknown hosts return 404. Requires a session and same-origin request. The host detail page offers Delete only after revoke and returns to the client detail after success. The agent remains installed on the VM.
- Tokens are stored hashed (e.g. SHA-256), not in plaintext
- Tokens stay required over Tailscale: the tailnet is shared by all clients' VMs, so network reachability does not prove which client a host belongs to. Enroll tokens are single-use and bound to a client; host tokens are issued to and stored by each agent.
- Validate that a host can only write to its own client
- Simple per-token rate limiting
- Request size limits, read/write timeouts
- TLS is handled by the operator's reverse proxy in front of central (nginx, Traefik, `tailscale serve`, ...); central listens on plain HTTP bound to 127.0.0.1 or a private interface. Central itself sets the security headers (CSP, HSTS, frame/nosniff/referrer) and enforces `CENTRAL_ADMIN_ALLOW_CIDRS` on the dashboard, `/api/admin` and `/mcp` (agents never restricted)

### Database schema (SQLite, as migrations)
- `clients` (id, name unique, scan_config JSON NULL, created_at)
- `enroll_tokens` (id, client_id, token_hash, created_at, revoked_at)
- `hosts` (id, client_id, hostname, host_token_hash, os_family, os_name, os_version, arch, kernel_running, agent_version, trivy_version, reboot_required, auto_update_enabled, last_heartbeat_at, last_scan_at, last_scan_status, created_at, revoked_at; UNIQUE(client_id, hostname))
- `scans` (id, host_id, scanned_at, status, error_message, duration_seconds, total, critical, high, trivy_version)
- `host_software` (host_id, name, path, version; PK host_id+name+path), `eol_cycles` (product, cycle, eol, latest, fetched_at; PK product+cycle)
- `findings` (id, host_id, target, type, cve, pkg, pkg_path, component_kind, component, installed_version, fixed_version, severity, title, first_seen, last_seen, resolved_at NULL, status CHECK IN ('open','accepted','false_positive') default 'open', note; UNIQUE(host_id, finding_key) where finding_key = SHA-256(cve, pkg, installed_version, target[, pkg_path when set]): one short unique key)
- Times are UTC, stored as text `2006-01-02 15:04:05.999999999-07:00` (`_time_format=sqlite`), so `date()` and string comparison work; SQL-computed times (MIN/MAX/date()) come back as text and are read via `entity.SQLTime`. Hashes are 32-byte BLOBs. Transactions use `BEGIN IMMEDIATE` (`_txlock=immediate`) instead of `SELECT ... FOR UPDATE`; one connection (`SetMaxOpenConns(1)`), so never use `c.DB` inside an open transaction
- Indexes needed for dashboard queries

### Report ingest logic (in a single transaction)
1. Insert a `scans` row.
2. For each finding: upsert into `findings`, update `last_seen`, and set `resolved_at = NULL` if it was previously resolved.
3. Findings for that host with `resolved_at IS NULL` that are not in this scan → set `resolved_at = NOW()`.
4. If the scan status is `error`, DO NOT perform steps 2–3 (do not mark findings resolved just because a scan failed).
5. Update `hosts.last_scan_at` and `last_scan_status`.

## Dashboard (admin web UI)
Admin-only SPA; admins see every client (no per-client logins). Dark only, palette after owasp.org (ink `#101820`, OWASP blues, cyan `#00a7e1`, gold `#ffb81b`; severity red/orange), Rubik + Space Grotesk self-hosted via `@fontsource`. Shell: shadcn-vue Sidebar variant `inset` (groups Monitor / Manage, user + sign out in the footer, breadcrumb in the inset header). Views:
1. Hosts (home): issue-stream list, worst first (`worstFirst` in `rules.ts`); tabs Needs attention / All / Not reporting / Revoked with counts; client filter + sort; search; per row a severity stripe (`hostLevel`), a 14-day sparkline from `/trend?host_id=`, open critical/high, last scan
2. Host detail (`/hosts/:id`): host facts and issues, counters (open critical/high, last scan), the re-scan command, revoke; tabs What to fix / Findings; right sidebar with last scan (resolved / new), host details, and tags. "What to fix" lists the host's components (tabs Open / Accepted / False positive). Each expands to a plain-language next step, a copy-ready fix command (`componentAdvice` in `src/lib/rules.ts`: apt/dnf upgrade, purge of a non-running fallback kernel vs upgrade + reboot of the running one, composer/npm/pip per app type, `dpkg -S`/`rpm -qf` for binaries), a bulk verdict for the whole component, and its CVEs with per-finding triage
3. Search CVEs (`/findings`): flat list across hosts; filter by client, host, severity, triage status, CVE/package search; paging; triage
4. Clients: cards with a 14-day sparkline (`/trend?client=`); create clients and configure per-client scan overrides
5. Account (`/account`, from the sidebar user): profile, change password (`POST /api/admin/v1/me/password`; signs out the admin's other sessions), active sessions with device/IP (`GET /me/sessions`, `DELETE /me/sessions/:id`, `DELETE /me/sessions` = all others)
6. MCP (`/mcp`, sidebar Manage): create/revoke MCP tokens (`/api/admin/v1/mcp-tokens`, per admin, shown once) and copy-ready setup per AI client (`mcpClientConfigs` in `src/lib/rules.ts`: Claude Code, Codex, OpenCode, Antigravity, Cursor, Claude Desktop via `mcp-remote`)

Rules:
- Components (`domain.Finding.Component`, stored at ingest and refreshed every scan) group findings into one upgrade action each: `os` = OS packages with the same installed version (one source package, e.g. all `linux-*` kernel pieces; shown as "Linux kernel" + reboot hint), `app` = language packages under one application folder (from Trivy's `PkgPath`, cut before `vendor/`, `node_modules/`, `site-packages/`, `.venv/`, `WEB-INF/`…; package caches like `.m2`/`.cache` group as the cache), `binary` = one Go/Rust binary. `POST /api/admin/v1/components/triage` applies one verdict to every unresolved finding of a component. Host rows carry `new_in_last_scan` / `resolved_in_last_scan` (findings whose `first_seen` / `resolved_at` equal the host's last successful `last_scan_at`) and `first_scan`.
- "Open" = `resolved_at IS NULL AND status = 'open'`. Triage (`accepted` / `false_positive`) takes an optional note and survives re-scans; it never deletes data.
- Auth: `admin_users` (bcrypt) + `admin_sessions` (SHA-256 token hash, 12h, plus login IP and User-Agent for the Account page). Cookie `vuln_session`: HttpOnly, Secure, SameSite=Strict, Path=/api/admin. State-changing requests must send a same-origin `Origin` (CSRF). Login limited per client IP; behind a reverse proxy set `CENTRAL_TRUST_PROXY=true` (compose default).
- Admins are created with the CLI only: `central admin create|passwd|list` (no sign-up).
- Admin API JSON shapes live in `core/internal/model` (not part of the agent contract in the agent module's `wire`); the dashboard's `apis/http.ts` unwraps `data` and reads `paging` / `errors`.
- Dashboard structure: `src/types` contains models, `src/lib` contains pure rules, `src/apis` contains HTTP access and validation, and `src/pages`, `src/components`, and `src/composables` contain the UI. Views never call `fetch`.
- Production CSP is `default-src 'self'`: no remote fonts/scripts/styles (a vitest guard checks `style.css`).

## End of life
- Separate from CVEs: agents (v0.3.0+) send `software` with each report (`wire.Software`: runtimes/DBs from local version commands, pm2 from its `package.json`, frameworks from lockfiles). Central replaces `host_software` on each successful report (an empty list from an older agent keeps the previous rows) and adds the host OS (`entity.OSSoftware`).
- `serve` refreshes `eol_cycles` from endoflife.date (`CENTRAL_EOL_URL`, default `https://endoflife.date/api`) on start and every 24 h; a failed product keeps its last data. Names map to products in `entity.EOLProducts`; the cycle is the longest one that prefixes the version at a dot (`entity.MatchCycle`); status `eol` / `soon` (≤ 90 days) / `supported` / `unknown`.
- Hosts carry `eol` / `eol_soon` labels (e.g. `php 7.4`), shown as host issues (`hostIssues`); EOL counts as "attention". `GET /api/admin/v1/hosts/:id/software` backs the host page's Software tab.

## MCP
- `/mcp` is a read-only MCP server (Streamable HTTP, stateless, JSON responses; official `github.com/modelcontextprotocol/go-sdk`) in `core/internal/delivery/mcp`. Tools `list_clients`, `list_hosts`, `search_findings` (25/page), `host_components` call the same use cases as the admin API and return its models.
- Auth: `Authorization: Bearer <mcp token>` (`mcp_tokens`, SHA-256 hash, bound to the admin who created it, `last_used_at` at most once a minute, revoke = `revoked_at`). Own rate limit (`Limits.McpMax`, default 600/min per admin and in total), separate from the agent limits; hits are logged (`MCP rate limited`). `search_findings` takes `page_size` 1-100 (default 25). `/mcp` is behind `ADMIN_ALLOW_CIDRS`.
- Tokens are read-only unless created with "Allow triage" (`mcp_tokens.can_triage`): only then `triage_finding` / `triage_component` are listed (destructive hint, so clients confirm). Their notes get `[via MCP: <token name>]` and central logs each verdict. The server is built per request from the token's `Auth`. No LLM calls inside central.

## Deployment
- `docker-compose.yml` (repo root, image from `Dockerfile`): `central` only (distroless; `serve` applies migrations; database `/data/central.db` on the `central_data` volume, daily `VACUUM INTO` backup to `/data/backups` at `BACKUP_AT`, kept `BACKUP_KEEP_DAYS`, also `central backup <file>`; dashboard SPA baked in at `/srv/dashboard`, published on `CENTRAL_PORT`, default `127.0.0.1:8080`, for the operator's HTTPS reverse proxy; the session cookie is Secure, so the dashboard needs HTTPS; optional `ADMIN_ALLOW_CIDRS`; healthcheck `central healthcheck`). Configure via `.env` (from `.env.example`); first admin: `docker compose exec central central admin create <name>`. `.dockerignore` keeps `dev-out/` and other local data out of the build context.
- Local dev: `make dev` runs central (SQLite in `dev-out/central.db`) (port 18080: Tailscale IP if up, else 127.0.0.1) + the dashboard (http://localhost:11270) in one terminal; Ctrl+C stops all, and if either process dies the other is stopped too. It migrates and seeds admin `admin` once (password in `dev-out/admin-password`). `make help` lists targets; `make dev-reset` deletes the dev DB; admin CLI via `make central ARGS="..."`.
- Sample VM loop over Tailscale: `make dev` listens on the laptop's Tailscale IP when `tailscale` is up (else `127.0.0.1:18080`; override with `CENTRAL_ADDR`), create the client in the dashboard, then in the agent repo `make scan-dev ARGS="-e @<enroll-vars.yml>"` (a mode-600 file with `vuln_agent_enroll_token`, never committed; add `-e vuln_agent_force_enroll=true` after the dev DB was reset).
- Tests: `make test` (dashboard tests, `go vet`, Go tests; no Docker: the suite creates a temp SQLite file).

## CI
- GitLab CI: lint, test, build; central image to the GitLab Container Registry (agent packaging and CI live in the agent repo)

## Testing
- All Go tests live in `core/test/` (package `test`, black-box, testify): requests go through the Fiber app (`app.Test`) into a real SQLite database; no fakes. `ClearAll` empties the tables per test; tests change timestamps in the DB instead of injecting a clock.
- Cover ingest logic (new finding, still present, resolved, reappeared, scan error), agent status codes and contract (strict decode of responses), tenant isolation (client A token rejected for client B), admin auth/session/CSRF, dashboard queries, and the pure entity rules

## Documentation (`/docs`)
- README: short architecture (text diagram), how to deploy central, how to enroll a new VM (link to the agent repo), how to revoke a host
- Security notes: data retention in central (what the agent reads/sends is documented in the agent repo)
- Troubleshooting: large report size, enroll/revoke issues

## Phases
1. **Phase 1**: agent (done; now in the agent repo)
2. **Phase 2**: DB schema + migrations, central API (enroll, heartbeat, config, report) + tests, following the contract in the agent module's `wire`
3. **Phase 3**: central Docker Compose + admin dashboard (Vue) + admin API
4. **Phase 4**: agent packaging + systemd + CI (agent repo); central CI here
5. **Phase 5**: finalize the Ansible role (agent repo) + documentation

## Out of Scope (do not build)
- Remote command execution in the agent
- Agent auto-update from central
- Secret, misconfig, or license scanning (vuln only for now)
- AI/LLM calls inside central or the agent (the read-only MCP server for external AI clients is in scope)
