-- ix_admin_sessions_user stays: InnoDB dropped its implicit FK index when it was added.
ALTER TABLE admin_sessions
  DROP COLUMN user_agent,
  DROP COLUMN ip;
