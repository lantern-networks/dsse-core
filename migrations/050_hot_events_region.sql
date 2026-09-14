-- The PostgreSQL hot store writes and filters this field on every regional event.
ALTER TABLE hot_events ADD COLUMN IF NOT EXISTS edge_region_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS hot_events_region_idx ON hot_events (tenant_id, edge_region_id, occurred_at DESC);
