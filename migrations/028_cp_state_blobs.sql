-- cp_state_blobs: shared durable snapshots for the control plane's authored-state stores (policy rules, grants,
-- approvals, overlays, catalogs, …). Each store persists its whole in-memory snapshot as one opaque blob keyed by
-- store_key. Moving these off node-local JSON files onto shared Postgres makes the CP stateless-over-Postgres so a
-- standby can serve the state the active authored — the prerequisite for CP HA / failover.
CREATE TABLE IF NOT EXISTS cp_state_blobs (
  store_key text PRIMARY KEY,
  payload bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
