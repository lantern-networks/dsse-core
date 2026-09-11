-- 038: deleted tenants are recorded by name, because a deletion has to be CARRIED to reach an Edge.
--
-- ★ THE MEASURED DEFECT (2026-08-15). The config bundle carries the tenant registry and UPSERTs it — on
-- purpose: an empty or truncated tenant section must never read as "delete everything", because that is also
-- what a control plane which is not the authority for tenants looks like, and the receiving end cannot tell
-- the two apart. The consequence was that deletion propagated nowhere. On the lab the control plane listed 2
-- tenants while the Edge listed 5, and the three ghosts came off only by editing the Edge's file by hand.
--
-- So the deletion is named rather than inferred. This table is the record of "the authority deleted this
-- tenant, at this instant", the file store keeps the same thing in its snapshot, and the bundle carries it so
-- an Edge removes a tenant because it was TOLD to. Absence still means nothing at all.
--
-- The row is removed when the same tenant id is created again: a re-creation supersedes the deletion, and
-- leaving the tombstone would make the next bundle ask every Edge to delete the tenant that was just made.
CREATE TABLE IF NOT EXISTS admin_tenant_model_deletions (
	tenant_id text NOT NULL,
	deleted_at timestamptz NOT NULL,
	PRIMARY KEY (tenant_id)
);
