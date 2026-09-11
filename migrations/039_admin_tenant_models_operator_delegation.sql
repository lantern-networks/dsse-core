-- The organization's standing delegation to the operator, and the record of who last moved it.
--
-- Without these columns the Postgres tenant-model store silently drops the delegation: PUT
-- /admin/operator-delegation returns 200, the next read answers false, and the operator is refused inside every
-- customer that has granted it. The file store persisted all three from the start, so the two backends
-- disagreed about the one field that decides whether the operator envelope works at all.
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS operator_managed boolean NOT NULL DEFAULT false;
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS operator_delegation_changed_at timestamptz;
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS operator_delegation_changed_by text NOT NULL DEFAULT '';
