CREATE TABLE IF NOT EXISTS admin_export_jobs (
  tenant_id text NOT NULL,
  export_job_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, export_job_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_export_jobs_export_job_id_unique_idx ON admin_export_jobs (export_job_id);

CREATE INDEX IF NOT EXISTS admin_export_jobs_tenant_created_idx ON admin_export_jobs (tenant_id, created_at DESC, export_job_id);

CREATE INDEX IF NOT EXISTS admin_export_jobs_tenant_status_idx ON admin_export_jobs (tenant_id, status, created_at DESC);
