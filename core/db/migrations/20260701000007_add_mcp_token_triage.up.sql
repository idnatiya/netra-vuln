-- MCP tokens are read-only unless created with "Allow triage".

ALTER TABLE mcp_tokens ADD COLUMN can_triage BOOLEAN NOT NULL DEFAULT FALSE AFTER token_hash;
