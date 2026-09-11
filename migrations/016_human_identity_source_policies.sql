CREATE TABLE IF NOT EXISTS human_identity_source_policies (
  tenant_id text NOT NULL,
  source text NOT NULL,
  connector_type text NOT NULL CHECK (connector_type IN ('generic', 'scim', 'oidc', 'hris', 'csv', 'manual')),
  enabled boolean NOT NULL DEFAULT true,
  reconcile_missing boolean NOT NULL DEFAULT false,
  expected_interval_seconds integer NOT NULL DEFAULT 0 CHECK (expected_interval_seconds >= 0),
  stale_after_seconds integer NOT NULL DEFAULT 0 CHECK (stale_after_seconds >= 0),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source)
);

CREATE INDEX IF NOT EXISTS human_identity_source_policies_enabled_idx ON human_identity_source_policies (tenant_id, enabled, source);
