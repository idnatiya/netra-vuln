-- Dashboard admins. Passwords are bcrypt hashes; session tokens are SHA-256 hashes.

CREATE TABLE admin_users (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(64)     NOT NULL,
  password_hash VARCHAR(100)    NOT NULL,
  created_at    DATETIME(6)     NOT NULL,
  disabled_at   DATETIME(6)     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE admin_sessions (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    BIGINT UNSIGNED NOT NULL,
  token_hash BINARY(32)      NOT NULL,
  created_at DATETIME(6)     NOT NULL,
  expires_at DATETIME(6)     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_sessions_token (token_hash),
  KEY ix_admin_sessions_expires (expires_at),
  CONSTRAINT fk_admin_sessions_user FOREIGN KEY (user_id) REFERENCES admin_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX ix_findings_status ON findings (status);
