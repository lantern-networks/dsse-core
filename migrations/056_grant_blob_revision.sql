-- A revision stamped at the shared write boundary lets current CP readers
-- avoid transferring both complete grant blobs on every unchanged refresh.
-- The trigger also sees updates by the released map-only CP writer. A sequence,
-- rather than a per-row counter or updated_at, prevents delete/reinsert ABA.
CREATE SEQUENCE IF NOT EXISTS dsse_grant_blob_revision_seq AS bigint;
ALTER TABLE cp_state_blobs
  ADD COLUMN IF NOT EXISTS grant_revision bigint NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION dsse_stamp_grant_blob_revision() RETURNS trigger
LANGUAGE plpgsql AS $grant_revision$
BEGIN
  IF NEW.store_key IN ('grants', 'grants_evidence_v1') THEN
    NEW.grant_revision := nextval('dsse_grant_blob_revision_seq');
  END IF;
  RETURN NEW;
END;
$grant_revision$;

DROP TRIGGER IF EXISTS dsse_grant_blob_revision_stamp ON cp_state_blobs;
CREATE TRIGGER dsse_grant_blob_revision_stamp
  BEFORE INSERT OR UPDATE ON cp_state_blobs
  FOR EACH ROW EXECUTE FUNCTION dsse_stamp_grant_blob_revision();
