CREATE TABLE IF NOT EXISTS application_catalog_legacy_imports (
  tenant_id text NOT NULL,
  application_id text NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, application_id)
);
CREATE TABLE IF NOT EXISTS application_catalog_legacy_import_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  source_sha256 text NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now()
);
