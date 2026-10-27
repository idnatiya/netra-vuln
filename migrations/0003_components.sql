-- Group findings into components (one upgrade action): an OS source package,
-- an application folder, or a binary. Filled by report ingest; see domain.Finding.Component.

ALTER TABLE findings
  ADD COLUMN pkg_path       VARCHAR(1024) NOT NULL DEFAULT '' AFTER pkg,
  ADD COLUMN component_kind VARCHAR(8)    NOT NULL DEFAULT '' AFTER pkg_path,
  ADD COLUMN component      VARCHAR(512)  NOT NULL DEFAULT '' AFTER component_kind,
  ADD KEY ix_findings_host_component (host_id, component_kind, component);
