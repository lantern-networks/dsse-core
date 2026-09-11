CREATE TABLE IF NOT EXISTS admin_sites (
  tenant_id text NOT NULL,
  site_id text NOT NULL,
  name text NOT NULL DEFAULT '',
  region text NOT NULL DEFAULT '',
  expected_connector_count integer NOT NULL DEFAULT 0,
  routing_namespace text NOT NULL DEFAULT '',
  deployment_type text NOT NULL DEFAULT '',
  ha_policy text NOT NULL DEFAULT '',
  bootstrap_secret_hash text NOT NULL DEFAULT '',
  bootstrap_secret_rotated_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, site_id)
);

CREATE INDEX IF NOT EXISTS admin_sites_tenant_idx ON admin_sites (tenant_id, site_id);
