-- Installed product versions per host (runtimes, databases, pm2, lockfile
-- frameworks), replaced on every successful report; checked against end-of-life data.
CREATE TABLE host_software (
  host_id INTEGER NOT NULL REFERENCES hosts (id),
  name    TEXT    NOT NULL,
  path    TEXT    NOT NULL DEFAULT '',
  version TEXT    NOT NULL,
  PRIMARY KEY (host_id, name, path)
);

-- Release cycles from endoflife.date, refreshed daily by central.
-- eol: YYYY-MM-DD, or 'true' / 'false' when the source gives no date.
CREATE TABLE eol_cycles (
  product    TEXT     NOT NULL,
  cycle      TEXT     NOT NULL,
  eol        TEXT     NOT NULL,
  latest     TEXT     NOT NULL DEFAULT '',
  fetched_at DATETIME NOT NULL,
  PRIMARY KEY (product, cycle)
);
