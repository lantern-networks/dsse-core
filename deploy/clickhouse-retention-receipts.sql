-- Run once, with ALL control-plane retention workers stopped.
-- First remove the old independent TTLs (clickhouse-preserve-logs.sql).
-- This is for a table WITHOUT retention_id: inspect system.columns first.
-- Never rematerialize an existing receipt column: pending deletion journals refer to its IDs.
ALTER TABLE dsse.events ADD COLUMN retention_id UUID DEFAULT generateUUIDv4() AFTER event_id;
ALTER TABLE dsse.events MATERIALIZE COLUMN retention_id SETTINGS mutations_sync = 2;
