CREATE TABLE IF NOT EXISTS human_identity_source_states (
  tenant_id text NOT NULL,
  source text NOT NULL,
  status text NOT NULL CHECK (status IN ('success', 'error', 'unknown')),
  last_import_run_id text,
  checkpoint text,
  last_success_at timestamptz,
  last_error_at timestamptz,
  last_error text,
  requested integer NOT NULL DEFAULT 0 CHECK (requested >= 0),
  upserted integer NOT NULL DEFAULT 0 CHECK (upserted >= 0),
  deactivated integer NOT NULL DEFAULT 0 CHECK (deactivated >= 0),
  active_count integer NOT NULL DEFAULT 0 CHECK (active_count >= 0),
  payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source)
);

CREATE INDEX IF NOT EXISTS human_identity_source_states_status_idx ON human_identity_source_states (tenant_id, status, updated_at);
