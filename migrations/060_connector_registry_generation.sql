-- A catalog version must survive deletion of the row with the latest updated_at.
-- The initial value matches what an older binary reports from the rows present at migration time.
-- A historical maximum cannot be recovered from the old schema after an earlier deletion.
CREATE TABLE IF NOT EXISTS connector_registry_generation (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  generation bigint NOT NULL CHECK (generation >= 0)
);

INSERT INTO connector_registry_generation (singleton, generation)
SELECT true, count(*) + COALESCE(EXTRACT(EPOCH FROM max(updated_at))::bigint, 0)
FROM connector_registrations
ON CONFLICT (singleton) DO NOTHING;
