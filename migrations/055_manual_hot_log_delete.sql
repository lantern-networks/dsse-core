-- The audit of an irreversible hot-log deletion is deliberately outside
-- hot_events and cannot be selected by another deletion job.
CREATE TABLE IF NOT EXISTS manual_hot_log_delete_jobs (
  job_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  stream text NOT NULL,
  cutoff timestamptz NOT NULL,
  preview_at timestamptz,
  mutation_id text NOT NULL DEFAULT '',
  requested_by text NOT NULL,
  store_kind text NOT NULL CHECK (store_kind IN ('postgres', 'clickhouse')),
  store_identity text NOT NULL,
  status text NOT NULL CHECK (status IN ('previewing','preview_ready','queued','running','completed','failed','stale')),
  preview_count bigint NOT NULL DEFAULT 0,
  deleted_count bigint NOT NULL DEFAULT 0,
  already_missing_count bigint NOT NULL DEFAULT 0,
  preview_digest text NOT NULL DEFAULT '',
  failure_code text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  finished_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS manual_hot_log_delete_pending_idx ON manual_hot_log_delete_jobs (status, created_at);
CREATE TABLE IF NOT EXISTS manual_hot_log_delete_candidates (
  job_id text NOT NULL REFERENCES manual_hot_log_delete_jobs(job_id) ON DELETE CASCADE,
  receipt text NOT NULL,
  row_at timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'done')),
  PRIMARY KEY(job_id, receipt)
);
CREATE INDEX IF NOT EXISTS manual_hot_log_delete_candidates_pending_idx ON manual_hot_log_delete_candidates (job_id, state, row_at, receipt);

-- Once ClickHouse has accepted an asynchronous mutation, a newly accepted
-- legal hold could falsely promise to preserve rows that are still being
-- removed. Serialize with the policy row locked by the deletion worker and
-- refuse a hold for that tenant until the mutation has been reconciled.
CREATE OR REPLACE FUNCTION manual_hot_log_delete_guard_new_hold() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  document jsonb;
  holds jsonb;
BEGIN
  IF NEW.store_key <> 'legal_hold' THEN
    RETURN NEW;
  END IF;
  document := convert_from(NEW.payload, 'UTF8')::jsonb;
  IF jsonb_typeof(document) = 'array' THEN
    holds := document;
  ELSE
    holds := COALESCE(document->'holds', '[]'::jsonb);
  END IF;
  IF EXISTS (
    SELECT 1 FROM manual_hot_log_delete_jobs j
    JOIN LATERAL jsonb_array_elements(holds) h ON h->>'tenant_id' = j.tenant_id
    WHERE j.store_kind = 'clickhouse' AND j.status = 'running'
  ) THEN
    RAISE EXCEPTION 'ClickHouse manual deletion is still active for this tenant'
      USING ERRCODE = '55000', CONSTRAINT = 'manual_hot_log_delete_running';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS manual_hot_log_delete_guard_new_hold ON cp_state_blobs;
CREATE TRIGGER manual_hot_log_delete_guard_new_hold
  BEFORE INSERT OR UPDATE OF payload ON cp_state_blobs
  FOR EACH ROW EXECUTE FUNCTION manual_hot_log_delete_guard_new_hold();
