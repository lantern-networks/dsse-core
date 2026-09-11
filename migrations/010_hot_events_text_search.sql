CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS hot_events_payload_text_trgm_idx ON hot_events USING gin ((lower(payload::text)) gin_trgm_ops);
