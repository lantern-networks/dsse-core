-- The trust half of a device's report, which this table silently dropped.
--
-- Since 027 the report grew the fields every PKI gate reads: which transport CAs the device pins and at
-- which distribution serial, which interception roots it holds, what it REFUSED to trust, and the fallback
-- credential it would present if its renewed identity broke. The in-memory backend carried them; this one
-- recorded the row and discarded exactly the fields the anchor-withdraw and CA-retire gates decide on — a
-- deployment on the postgres backend would have shown every device silent and every retirement green.
--
-- Additive and defaulted: rows written before this migration read as "the device did not say", which is how
-- every consumer already treats an agent that has not reported.
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS pinned_transport_ca_sha256 jsonb NOT NULL DEFAULT '[]';
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS adopted_trust_serial bigint NOT NULL DEFAULT 0;
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS pinned_interception_root_sha256 jsonb NOT NULL DEFAULT '[]';
-- The interception root a device is PINNED to, as distinct from the ones above that it happens to HOLD.
--
-- ★ THE TWO ARE DIFFERENT FACTS AND THE DIFFERENCE DECIDES A WITHDRAWAL (2026-08-16). The column above is what
-- the agent FOUND in its trust store — a machine can hold three roots for three unrelated reasons. This one is
-- what the agent was INSTALLED with and refuses to work without: the single authority its configuration names.
-- Ending a replacement overlap needs the second. "Every device holds the new root" does not make it safe to
-- stop announcing the old one: an agent pinned to the old root and armed stands aside the moment the Edge
-- stops naming it, whatever else is in its trust store. Empty means the agent HAS NOT SAID — unknown, never
-- "not pinned".
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS interception_root_pin_sha256 text NOT NULL DEFAULT '';
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS trust_refusals jsonb NOT NULL DEFAULT '[]';
ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS fallback_client_cert_pem text NOT NULL DEFAULT '';
