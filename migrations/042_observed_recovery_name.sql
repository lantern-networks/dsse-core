-- 042_observed_recovery_name.sql — what recovery name a device says it holds.
--
-- ★★★ THE DURABLE BACKEND SILENTLY DROPPED A FIELD THE IN-MEMORY ONE CARRIED (2026-08-19).
--
-- renewal_recovery_sni_sent was added to the reported record and to the in-memory store, and the Postgres
-- store — the one a deployment uses when the answer has to survive a restart — had no column for it. So the
-- reference lab, switched to the durable backend precisely BECAUSE the port-closing gate reads it, then
-- answered "every device is silent" about two devices that were reporting the name every minute.
--
-- The gate this feeds decides whether the dedicated renewal-recovery port may be closed. Dropping the field
-- makes that decision unanswerable; carrying it in memory only makes it unanswerable after a restart, and
-- different on each Edge.
ALTER TABLE observed_steer_exclusions
  ADD COLUMN IF NOT EXISTS renewal_recovery_sni_sent text NOT NULL DEFAULT '';

-- And a second field the durable backend never carried, found by the gate added with this migration:
-- what the device received and deliberately DID NOT apply. The console states the device's own reason from
-- it; without the column a Postgres deployment shows "did not say" for every device, which is not the same
-- statement and is indistinguishable from an agent too old to report it.
ALTER TABLE observed_steer_exclusions
  ADD COLUMN IF NOT EXISTS ignored_app_signing_ids jsonb NOT NULL DEFAULT '[]';