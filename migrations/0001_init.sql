-- All timestamps are UTC, written by the application (DATETIME(6)).
-- Tokens are stored only as SHA-256 hashes.

CREATE TABLE clients (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name        VARCHAR(64)     NOT NULL,
  -- Per-client scan overrides in the wire.ScanConfig format; NULL = agent defaults.
  scan_config JSON            NULL,
  created_at  DATETIME(6)     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_clients_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE enroll_tokens (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_id  BIGINT UNSIGNED NOT NULL,
  token_hash BINARY(32)      NOT NULL,
  created_at DATETIME(6)     NOT NULL,
  revoked_at DATETIME(6)     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_enroll_tokens_hash (token_hash),
  KEY ix_enroll_tokens_client (client_id),
  CONSTRAINT fk_enroll_tokens_client FOREIGN KEY (client_id) REFERENCES clients (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE hosts (
  id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_id           BIGINT UNSIGNED NOT NULL,
  hostname            VARCHAR(255)    NOT NULL,
  host_token_hash     BINARY(32)      NOT NULL,
  os_family           VARCHAR(32)     NOT NULL DEFAULT '',
  os_name             VARCHAR(128)    NOT NULL DEFAULT '',
  os_version          VARCHAR(64)     NOT NULL DEFAULT '',
  arch                VARCHAR(16)     NOT NULL DEFAULT '',
  kernel_running      VARCHAR(128)    NOT NULL DEFAULT '',
  agent_version       VARCHAR(64)     NOT NULL DEFAULT '',
  trivy_version       VARCHAR(64)     NOT NULL DEFAULT '',
  reboot_required     BOOLEAN         NOT NULL DEFAULT FALSE,
  auto_update_enabled BOOLEAN         NOT NULL DEFAULT FALSE,
  last_heartbeat_at   DATETIME(6)     NULL,
  last_scan_at        DATETIME(6)     NULL,
  last_scan_status    ENUM('ok','error') NULL,
  created_at          DATETIME(6)     NOT NULL,
  revoked_at          DATETIME(6)     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_hosts_client_hostname (client_id, hostname),
  UNIQUE KEY uq_hosts_token_hash (host_token_hash),
  KEY ix_hosts_client_heartbeat (client_id, last_heartbeat_at),
  KEY ix_hosts_last_scan (last_scan_at),
  CONSTRAINT fk_hosts_client FOREIGN KEY (client_id) REFERENCES clients (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE scans (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id          BIGINT UNSIGNED NOT NULL,
  scanned_at       DATETIME(6)     NOT NULL,
  status           ENUM('ok','error') NOT NULL,
  error_message    TEXT            NULL,
  duration_seconds DOUBLE          NOT NULL DEFAULT 0,
  total            INT UNSIGNED    NOT NULL DEFAULT 0,
  critical         INT UNSIGNED    NOT NULL DEFAULT 0,
  high             INT UNSIGNED    NOT NULL DEFAULT 0,
  trivy_version    VARCHAR(64)     NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY ix_scans_host_scanned (host_id, scanned_at),
  KEY ix_scans_scanned (scanned_at),
  CONSTRAINT fk_scans_host FOREIGN KEY (host_id) REFERENCES hosts (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE findings (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id           BIGINT UNSIGNED NOT NULL,
  -- SHA-256(cve, pkg, installed_version, target): a 5-column UNIQUE on the raw
  -- columns would exceed InnoDB's 3072-byte index key limit with utf8mb4.
  finding_key       BINARY(32)      NOT NULL,
  target            VARCHAR(512)    NOT NULL,
  type              VARCHAR(64)     NOT NULL,
  cve               VARCHAR(64)     NOT NULL,
  pkg               VARCHAR(255)    NOT NULL,
  installed_version VARCHAR(128)    NOT NULL,
  fixed_version     VARCHAR(255)    NOT NULL DEFAULT '',
  severity          ENUM('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
  title             VARCHAR(1024)   NOT NULL DEFAULT '',
  first_seen        DATETIME(6)     NOT NULL,
  last_seen         DATETIME(6)     NOT NULL,
  resolved_at       DATETIME(6)     NULL,
  status            ENUM('open','accepted','false_positive') NOT NULL DEFAULT 'open',
  note              TEXT            NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_findings_host_key (host_id, finding_key),
  KEY ix_findings_host_resolved (host_id, resolved_at),
  KEY ix_findings_resolved_severity (resolved_at, severity),
  KEY ix_findings_cve (cve),
  KEY ix_findings_first_seen (first_seen),
  CONSTRAINT fk_findings_host FOREIGN KEY (host_id) REFERENCES hosts (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
