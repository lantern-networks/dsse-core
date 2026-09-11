CREATE TABLE IF NOT EXISTS domain_event_outbox (
  tenant_id text NOT NULL,
  outbox_id text NOT NULL,
  schema_version text NOT NULL,
  event_plane text NOT NULL CHECK (event_plane IN ('domain', 'access', 'evidence')),
  stream text NOT NULL CONSTRAINT domain_event_outbox_stream_check CHECK (stream IN ('authentication_events', 'break_glass_events', 'device_events', 'agent_update_events', 'human_approval_events', 'delegated_access_grants', 'tool_call_events', 'inspection_events', 'access_logs', 'decision_traces', 'connector_logs')),
  event_type text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'publishing', 'published', 'dead')),
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  published_at timestamptz,
  dead_at timestamptz,
  publish_attempt integer NOT NULL DEFAULT 0 CHECK (publish_attempt >= 0),
  locked_by text,
  locked_until timestamptz,
  next_attempt_at timestamptz,
  last_error text,
  payload_checksum text NOT NULL CHECK (payload_checksum ~ '^sha256:[a-f0-9]{64}$'),
  payload jsonb NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, outbox_id)
);

CREATE INDEX IF NOT EXISTS domain_event_outbox_pending_idx ON domain_event_outbox (tenant_id, event_plane, status, next_attempt_at, occurred_at, outbox_id);
CREATE INDEX IF NOT EXISTS domain_event_outbox_stream_idx ON domain_event_outbox (tenant_id, stream, occurred_at DESC);
CREATE INDEX IF NOT EXISTS domain_event_outbox_event_idx ON domain_event_outbox (tenant_id, event_type, occurred_at DESC);
