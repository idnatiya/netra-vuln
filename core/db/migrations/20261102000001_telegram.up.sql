-- Telegram chats allowed to talk to the bot and receive alerts.
-- client_id NULL = admin chat (every client); else that client only.
CREATE TABLE telegram_chats (
  chat_id    INTEGER  PRIMARY KEY,
  client_id  INTEGER  NULL REFERENCES clients (id),
  created_at DATETIME NOT NULL
);

-- Notifier progress (last_scan_id, last_digest).
CREATE TABLE notify_state (
  key   TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL
);

-- Alerts currently raised per host (stale, error, eol label), so each is sent once.
CREATE TABLE notify_alerts (
  host_id INTEGER NOT NULL REFERENCES hosts (id),
  kind    TEXT    NOT NULL,
  label   TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (host_id, kind, label)
);
