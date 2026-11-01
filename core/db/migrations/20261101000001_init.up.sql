-- SQLite schema. All timestamps are UTC, written by the application as
-- "YYYY-MM-DD HH:MM:SS.ffffff+00:00" text (sortable, readable by date()).
-- Tokens are stored only as SHA-256 hashes (32-byte BLOBs).

CREATE TABLE clients (
  id          INTEGER PRIMARY KEY,
  name        TEXT     NOT NULL UNIQUE,
  -- Per-client scan overrides in the wire.ScanConfig format; NULL = agent defaults.
  scan_config TEXT     NULL,
  created_at  DATETIME NOT NULL
);

CREATE TABLE enroll_tokens (
  id         INTEGER PRIMARY KEY,
  client_id  INTEGER  NOT NULL REFERENCES clients (id),
  token_hash BLOB     NOT NULL UNIQUE,
  created_at DATETIME NOT NULL,
  revoked_at DATETIME NULL
);
CREATE INDEX ix_enroll_tokens_client ON enroll_tokens (client_id);

CREATE TABLE hosts (
  id                  INTEGER PRIMARY KEY,
  client_id           INTEGER  NOT NULL REFERENCES clients (id),
  hostname            TEXT     NOT NULL,
  host_token_hash     BLOB     NOT NULL UNIQUE,
  os_family           TEXT     NOT NULL DEFAULT '',
  os_name             TEXT     NOT NULL DEFAULT '',
  os_version          TEXT     NOT NULL DEFAULT '',
  arch                TEXT     NOT NULL DEFAULT '',
  kernel_running      TEXT     NOT NULL DEFAULT '',
  agent_version       TEXT     NOT NULL DEFAULT '',
  trivy_version       TEXT     NOT NULL DEFAULT '',
  reboot_required     BOOLEAN  NOT NULL DEFAULT FALSE,
  auto_update_enabled BOOLEAN  NOT NULL DEFAULT FALSE,
  last_heartbeat_at   DATETIME NULL,
  last_scan_at        DATETIME NULL,
  last_scan_status    TEXT     NULL CHECK (last_scan_status IN ('ok', 'error')),
  created_at          DATETIME NOT NULL,
  revoked_at          DATETIME NULL,
  UNIQUE (client_id, hostname)
);
CREATE INDEX ix_hosts_client_heartbeat ON hosts (client_id, last_heartbeat_at);
CREATE INDEX ix_hosts_last_scan ON hosts (last_scan_at);

CREATE TABLE scans (
  id               INTEGER PRIMARY KEY,
  host_id          INTEGER  NOT NULL REFERENCES hosts (id),
  scanned_at       DATETIME NOT NULL,
  status           TEXT     NOT NULL CHECK (status IN ('ok', 'error')),
  error_message    TEXT     NULL,
  duration_seconds REAL     NOT NULL DEFAULT 0,
  total            INTEGER  NOT NULL DEFAULT 0,
  critical         INTEGER  NOT NULL DEFAULT 0,
  high             INTEGER  NOT NULL DEFAULT 0,
  trivy_version    TEXT     NOT NULL DEFAULT ''
);
CREATE INDEX ix_scans_host_scanned ON scans (host_id, scanned_at);
CREATE INDEX ix_scans_scanned ON scans (scanned_at);

CREATE TABLE findings (
  id                INTEGER PRIMARY KEY,
  host_id           INTEGER  NOT NULL REFERENCES hosts (id),
  -- SHA-256(cve, pkg, installed_version, target[, pkg_path]): one short unique key.
  finding_key       BLOB     NOT NULL,
  target            TEXT     NOT NULL,
  type              TEXT     NOT NULL,
  cve               TEXT     NOT NULL,
  pkg               TEXT     NOT NULL,
  pkg_path          TEXT     NOT NULL DEFAULT '',
  -- Component (one upgrade action): an OS source package, an application folder,
  -- or a binary. Filled by report ingest; see entity.Vulnerability.Component.
  component_kind    TEXT     NOT NULL DEFAULT '',
  component         TEXT     NOT NULL DEFAULT '',
  installed_version TEXT     NOT NULL,
  fixed_version     TEXT     NOT NULL DEFAULT '',
  severity          TEXT     NOT NULL CHECK (severity IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  title             TEXT     NOT NULL DEFAULT '',
  first_seen        DATETIME NOT NULL,
  last_seen         DATETIME NOT NULL,
  resolved_at       DATETIME NULL,
  status            TEXT     NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'false_positive')),
  note              TEXT     NULL,
  UNIQUE (host_id, finding_key)
);
CREATE INDEX ix_findings_host_resolved ON findings (host_id, resolved_at);
CREATE INDEX ix_findings_resolved_severity ON findings (resolved_at, severity);
CREATE INDEX ix_findings_cve ON findings (cve);
CREATE INDEX ix_findings_first_seen ON findings (first_seen);
CREATE INDEX ix_findings_status ON findings (status);
CREATE INDEX ix_findings_host_component ON findings (host_id, component_kind, component);

-- Dashboard admins. Passwords are bcrypt hashes.
CREATE TABLE admin_users (
  id            INTEGER PRIMARY KEY,
  username      TEXT     NOT NULL UNIQUE,
  password_hash TEXT     NOT NULL,
  created_at    DATETIME NOT NULL,
  disabled_at   DATETIME NULL
);

CREATE TABLE admin_sessions (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER  NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
  token_hash BLOB     NOT NULL UNIQUE,
  -- Where the session signed in from, shown on the Account page.
  ip         TEXT     NOT NULL DEFAULT '',
  user_agent TEXT     NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL
);
CREATE INDEX ix_admin_sessions_expires ON admin_sessions (expires_at);
CREATE INDEX ix_admin_sessions_user ON admin_sessions (user_id);

-- Bearer tokens for the MCP endpoint (/mcp). Read-only unless can_triage.
CREATE TABLE mcp_tokens (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER  NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
  name         TEXT     NOT NULL,
  token_hash   BLOB     NOT NULL UNIQUE,
  can_triage   BOOLEAN  NOT NULL DEFAULT FALSE,
  created_at   DATETIME NOT NULL,
  last_used_at DATETIME NULL,
  revoked_at   DATETIME NULL
);
CREATE INDEX ix_mcp_tokens_user ON mcp_tokens (user_id);
