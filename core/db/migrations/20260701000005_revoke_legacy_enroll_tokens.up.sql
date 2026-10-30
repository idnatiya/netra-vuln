UPDATE enroll_tokens SET revoked_at = UTC_TIMESTAMP(6) WHERE revoked_at IS NULL;
