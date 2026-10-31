-- Bearer tokens for the MCP endpoint (/mcp), created from the dashboard. Only SHA-256 hashes are stored.

CREATE TABLE mcp_tokens (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id      BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(64)     NOT NULL,
  token_hash   BINARY(32)      NOT NULL,
  created_at   DATETIME(6)     NOT NULL,
  last_used_at DATETIME(6)     NULL,
  revoked_at   DATETIME(6)     NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_mcp_tokens_token (token_hash),
  KEY ix_mcp_tokens_user (user_id),
  CONSTRAINT fk_mcp_tokens_user FOREIGN KEY (user_id) REFERENCES admin_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
