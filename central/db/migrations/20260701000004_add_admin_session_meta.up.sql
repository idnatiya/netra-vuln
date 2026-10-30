-- Where a dashboard session signed in from, shown on the Account page.

ALTER TABLE admin_sessions
  ADD COLUMN ip         VARCHAR(45)  NOT NULL DEFAULT '' AFTER token_hash,
  ADD COLUMN user_agent VARCHAR(255) NOT NULL DEFAULT '' AFTER ip,
  ADD KEY ix_admin_sessions_user (user_id);
