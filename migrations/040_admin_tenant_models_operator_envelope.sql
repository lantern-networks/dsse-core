-- The rest of the operator envelope, and the tenant's clock.
--
-- Three more fields the Postgres tenant-model store could not carry:
--
--   operator_elevation_requires_approval — the organization's requirement that its OWN administrator approve an
--     elevation before it becomes active. Dropped, it reads false, and an elevation is created with
--     ApprovalRequired=false: the operator's irreversible acts proceed without the approval the customer asked
--     for. This one fails OPEN, unlike the standing delegation.
--
--   operator_elevations — every elevation ever taken over this organization. Dropped, the customer's "when they
--     used it" list is permanently empty: the transparency half of the envelope, gone.
--
--   timezone — the IANA zone this organization reads times in. Dropped, every organization reads UTC and the
--     setting silently does not stick.
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS operator_elevation_requires_approval boolean NOT NULL DEFAULT false;
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS operator_elevations jsonb NOT NULL DEFAULT '[]';
ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT '';
