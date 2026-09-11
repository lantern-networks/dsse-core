-- Enforce history preservation at the shared write boundary, including writers
-- from older binaries that do not decode the newer retirement/recovery fields.
-- Tenant erasure remains a row-array update; deleting a whole PKI store is not
-- an organization-erasure operation and would also erase the anonymous serial floor.
CREATE OR REPLACE FUNCTION dsse_guard_pki_history() RETURNS trigger
LANGUAGE plpgsql AS $pki_guard$
DECLARE
  before_doc jsonb;
  after_doc jsonb;
  previous_row jsonb;
  candidate_row jsonb;
BEGIN
  IF OLD.store_key NOT IN ('tenant_device_authorities', 'tenant_trust_distributions') THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'pki_history_regression: deleting the complete PKI store is forbidden' USING ERRCODE = '23514';
  END IF;
  IF NEW.store_key <> OLD.store_key THEN
    RAISE EXCEPTION 'pki_history_regression: moving the PKI store key is forbidden' USING ERRCODE = '23514';
  END IF;
  before_doc := convert_from(OLD.payload, 'UTF8')::jsonb;
  after_doc := convert_from(NEW.payload, 'UTF8')::jsonb;
  IF OLD.store_key = 'tenant_device_authorities' THEN
    IF jsonb_typeof(after_doc) IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'pki_history_regression: invalid device authority snapshot' USING ERRCODE = '23514';
    END IF;
    FOR previous_row IN SELECT value FROM jsonb_array_elements(before_doc) LOOP
      SELECT value INTO candidate_row FROM jsonb_array_elements(after_doc)
        WHERE lower(value->>'tenant_id') = lower(previous_row->>'tenant_id');
      -- A missing organization was erased. A surviving organization must retain
      -- every retired fingerprint, even when a different organization was edited.
      IF FOUND AND NOT (COALESCE(candidate_row->'retired_anchor_sha256', '[]'::jsonb)
          @> COALESCE(previous_row->'retired_anchor_sha256', '[]'::jsonb)) THEN
        RAISE EXCEPTION 'pki_history_regression: retired device authorities cannot be forgotten' USING ERRCODE = '23514';
      END IF;
    END LOOP;
  ELSE
    IF jsonb_typeof(after_doc) IS DISTINCT FROM 'object'
       OR COALESCE((after_doc->>'serial_floor')::bigint, -1) < COALESCE((before_doc->>'serial_floor')::bigint, 0)
       OR COALESCE((after_doc->>'recovery_history_version')::integer, 0) < COALESCE((before_doc->>'recovery_history_version')::integer, 0) THEN
      RAISE EXCEPTION 'pki_history_regression: canonical trust history cannot move backwards' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$pki_guard$;

CREATE TRIGGER dsse_pki_history_write_guard
BEFORE UPDATE OR DELETE ON cp_state_blobs
FOR EACH ROW EXECUTE FUNCTION dsse_guard_pki_history();
