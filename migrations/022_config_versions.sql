-- Config versioning + rollback (docs/config_persistence_and_rollback.md V-1). Every admin-managed config
-- change appends an immutable version row (the full resource snapshot) on the control plane, so an admin
-- can list history and roll back any resource to a prior version. Generic across resource types
-- (steer_exclusion first; later policy_bundle, certificate, tenant_restriction, east_west).
CREATE TABLE IF NOT EXISTS config_versions (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL,
  resource_type text NOT NULL,
  resource_id   text NOT NULL,
  version_no    bigint NOT NULL,
  payload       jsonb NOT NULL,
  action        text NOT NULL,           -- upsert | delete | rollback
  actor         text NOT NULL DEFAULT '',
  note          text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, resource_type, resource_id, version_no)
);
CREATE INDEX IF NOT EXISTS config_versions_lookup_idx
  ON config_versions (tenant_id, resource_type, resource_id, version_no DESC);
