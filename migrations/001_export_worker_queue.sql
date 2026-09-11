CREATE TABLE IF NOT EXISTS export_worker_tasks (
  tenant_id text NOT NULL,
  task_id text NOT NULL,
  export_job_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running')),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  retry_not_before timestamptz,
  lease_owner text,
  lease_expires_at timestamptz,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_id)
);

CREATE INDEX IF NOT EXISTS export_worker_tasks_lease_idx ON export_worker_tasks (tenant_id, status, retry_not_before, created_at, task_id);

CREATE INDEX IF NOT EXISTS export_worker_tasks_job_idx ON export_worker_tasks (tenant_id, export_job_id);

CREATE TABLE IF NOT EXISTS export_worker_task_dead_letters (
  tenant_id text NOT NULL,
  task_id text NOT NULL,
  export_job_id text NOT NULL,
  attempt integer NOT NULL CHECK (attempt >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts > 0),
  dead_letter_reason text NOT NULL,
  dead_lettered_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, task_id)
);

CREATE INDEX IF NOT EXISTS export_worker_task_dead_letters_job_idx ON export_worker_task_dead_letters (tenant_id, export_job_id);
