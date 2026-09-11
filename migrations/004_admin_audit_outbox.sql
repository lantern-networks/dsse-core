CREATE TABLE IF NOT EXISTS admin_audit_outbox (
  tenant_id text NOT NULL,
  outbox_id text NOT NULL,
  event_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'publishing', 'published', 'dead')),
  occurred_at timestamptz NOT NULL,
  published_at timestamptz,
  dead_at timestamptz,
  publish_attempt integer NOT NULL DEFAULT 0 CHECK (publish_attempt >= 0),
  locked_by text,
  locked_until timestamptz,
  next_attempt_at timestamptz,
  last_error text,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, outbox_id)
);

CREATE INDEX IF NOT EXISTS admin_audit_outbox_pending_idx ON admin_audit_outbox (tenant_id, status, next_attempt_at, occurred_at, outbox_id);
CREATE INDEX IF NOT EXISTS admin_audit_outbox_event_idx ON admin_audit_outbox (tenant_id, event_type, occurred_at DESC);
