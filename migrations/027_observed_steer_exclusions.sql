CREATE TABLE IF NOT EXISTS observed_steer_exclusions (
  tenant_id text NOT NULL,
  device_identity text NOT NULL,
  device_group text NOT NULL DEFAULT '',
  platform text NOT NULL DEFAULT '',
  effective_app_signing_ids jsonb NOT NULL DEFAULT '[]',
  admin_app_signing_ids jsonb NOT NULL DEFAULT '[]',
  unmanaged_app_signing_ids jsonb NOT NULL DEFAULT '[]',
  server_app_signing_id_count integer NOT NULL DEFAULT 0,
  reported_at timestamptz NOT NULL,
  posture text NOT NULL DEFAULT '',
  fail_open_configured boolean NOT NULL DEFAULT false,
  region_failover_enabled boolean NOT NULL DEFAULT false,
  active_region text NOT NULL DEFAULT '',
  server_initiated_rule_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, device_identity)
);

CREATE INDEX IF NOT EXISTS observed_steer_exclusions_tenant_reported_idx ON observed_steer_exclusions (tenant_id, reported_at DESC);

CREATE INDEX IF NOT EXISTS observed_steer_exclusions_effective_gin ON observed_steer_exclusions USING gin (effective_app_signing_ids jsonb_path_ops);
