CREATE TABLE IF NOT EXISTS connector_registrations (
  connector_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  connector_group_id text NOT NULL,
  name text NOT NULL,
  edge_region_id text NOT NULL,
  edge_cluster_id text NOT NULL,
  application_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  private_base_url text NOT NULL,
  status text NOT NULL CHECK (status IN ('registered', 'healthy', 'degraded', 'offline')),
  registered_at timestamptz NOT NULL,
  last_heartbeat_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS connector_registrations_tenant_status_idx ON connector_registrations (tenant_id, status);

CREATE INDEX IF NOT EXISTS connector_registrations_group_idx ON connector_registrations (tenant_id, connector_group_id);
