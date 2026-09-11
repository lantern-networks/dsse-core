CREATE TABLE IF NOT EXISTS usage_meter_records (
  tenant_id text NOT NULL,
  usage_meter_id text NOT NULL,
  schema_version text NOT NULL,
  meter_type text NOT NULL,
  subject_type text NOT NULL,
  subject_id text NOT NULL,
  unit text NOT NULL,
  quantity double precision NOT NULL CHECK (quantity >= 0),
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  collected_at timestamptz NOT NULL,
  quota jsonb,
  dimensions jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, usage_meter_id),
  CHECK (period_end > period_start)
);

CREATE INDEX IF NOT EXISTS usage_meter_records_period_idx ON usage_meter_records (tenant_id, period_start, period_end);

CREATE INDEX IF NOT EXISTS usage_meter_records_meter_idx ON usage_meter_records (tenant_id, meter_type, period_start);

CREATE INDEX IF NOT EXISTS usage_meter_records_subject_idx ON usage_meter_records (tenant_id, subject_type, subject_id, period_start);
