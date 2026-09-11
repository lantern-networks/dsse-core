CREATE TABLE IF NOT EXISTS hot_events (
tenant_id text NOT NULL,
stream text NOT NULL,
event_id text NOT NULL,
access_decision_id text,
occurred_at timestamptz NOT NULL,
received_at timestamptz NOT NULL DEFAULT now(),
payload jsonb NOT NULL,
PRIMARY KEY (tenant_id, stream, event_id)
);
CREATE INDEX IF NOT EXISTS hot_events_search_idx ON hot_events (tenant_id, stream, occurred_at DESC, received_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS hot_events_decision_idx ON hot_events (tenant_id, access_decision_id, occurred_at DESC, received_at DESC, event_id DESC);
