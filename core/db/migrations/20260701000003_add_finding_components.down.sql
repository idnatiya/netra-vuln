ALTER TABLE findings
  DROP KEY ix_findings_host_component,
  DROP COLUMN component,
  DROP COLUMN component_kind,
  DROP COLUMN pkg_path;
