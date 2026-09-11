-- Admin-managed steer exclusions: which app code-signing identifiers are excluded from steering, per scope
-- (tenant / device_group / device). Owned by the control plane (the admin authority) so admin-set exclusions
-- survive a restart. The resolved set is later signed and delivered to the agent (the user cannot change it).
CREATE TABLE IF NOT EXISTS steer_exclusion_policies (
  id                       text PRIMARY KEY,
  tenant_id                text NOT NULL,
  scope_type               text NOT NULL CHECK (scope_type IN ('tenant', 'device_group', 'device')),
  scope_id                 text NOT NULL DEFAULT '',
  excluded_app_signing_ids jsonb NOT NULL DEFAULT '[]',
  note                     text NOT NULL DEFAULT '',
  status                   text NOT NULL DEFAULT 'active',
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS steer_exclusion_policies_tenant_idx ON steer_exclusion_policies (tenant_id, scope_type, scope_id);
