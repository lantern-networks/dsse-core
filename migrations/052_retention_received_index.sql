CREATE INDEX IF NOT EXISTS hot_events_retention_idx ON hot_events (tenant_id, stream, received_at, event_id);
