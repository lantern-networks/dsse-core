-- For existing standard tables that still have TTL clauses (inspect SHOW CREATE TABLE first).
-- Run each statement only when its table has a TTL. Fresh schemas have none.
-- Previous default TTLs deleted events after 30 days and rollups after 400 days,
-- independently of Console legal holds and retention overrides. Disable those
-- deletions until ClickHouse has a retention worker that respects those controls.
-- This preserves remaining rows; it cannot recover records already expired.
ALTER TABLE dsse.events REMOVE TTL;
ALTER TABLE dsse.events_rollup_5m REMOVE TTL;
