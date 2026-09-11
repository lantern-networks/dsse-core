CREATE TABLE IF NOT EXISTS application_catalog (
  tenant_id text NOT NULL,
  application_id text NOT NULL,
  name text NOT NULL DEFAULT '',
  application_type text NOT NULL DEFAULT '',
  service_family text NOT NULL DEFAULT '',
  protocol text NOT NULL DEFAULT '',
  destination_role text NOT NULL DEFAULT '',
  application_sensitivity text NOT NULL DEFAULT '',
  route_ref text NOT NULL DEFAULT '',
  saas_provider text NOT NULL DEFAULT '',
  saas_category text NOT NULL DEFAULT '',
  saas_risk_tier text NOT NULL DEFAULT '',
  domain_pattern_count integer NOT NULL DEFAULT 0,
  sni_pattern_count integer NOT NULL DEFAULT 0,
  tags jsonb NOT NULL DEFAULT '[]',
  status text NOT NULL DEFAULT '',
  destination text NOT NULL DEFAULT '',
  destination_port integer NOT NULL DEFAULT 0,
  publish_protocol text NOT NULL DEFAULT '',
  connector_group_id text NOT NULL DEFAULT '',
  published boolean NOT NULL DEFAULT false,
  last_probe_at text,
  routing_namespace text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, application_id)
);

CREATE INDEX IF NOT EXISTS application_catalog_tenant_idx ON application_catalog (tenant_id, application_id);
