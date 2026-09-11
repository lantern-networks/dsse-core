CREATE TABLE IF NOT EXISTS admin_tenant_models (
  tenant_id text NOT NULL,
  display_name text NOT NULL,
  region text NOT NULL DEFAULT '',
  data_residency text NOT NULL DEFAULT '',
  allowed_regions jsonb NOT NULL DEFAULT '[]',
  home_region text NOT NULL DEFAULT '',
  plan text NOT NULL DEFAULT '',
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'archived')),
  policy_bundle_id text NOT NULL DEFAULT '',
  policy_bundle_version text NOT NULL DEFAULT '',
  metadata_key_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id)
);

CREATE INDEX IF NOT EXISTS admin_tenant_models_status_idx ON admin_tenant_models (status, tenant_id);
