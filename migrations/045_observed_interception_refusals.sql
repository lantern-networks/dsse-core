-- 045_observed_interception_refusals.sql — what a device's own probe found wrong with the certificates
-- INTERCEPTION served it, and the SNI it actually presents.
--
-- ★★★ THE THIRD REPORTED FIELD TO ARRIVE WITH NO READER (2026-08-22). win-dev-1 shipped 0.2.21, EV-signed and
-- measured on hardware, with an agent that opens one flow every fifteen minutes, lets the handshake COMPLETE
-- so the chain can be read, and verifies it TWICE — Go against a pool built from that machine's own root
-- stores, then the platform verifier — because on 2026-08-21 the same chain was accepted by Chrome and refused
-- by openssl, git and Node over pathLenConstraint:0. It posts what it refused. Nothing on this side named the
-- field, so all of it was discarded at the door, exactly like renewal_recovery_sni and renewal_recovery_target
-- before it.
--
-- transport_server_name_sent came with it, found by the gate written the same day: the SNI a device actually
-- presents is the evidence the enrolment fold turns on — whether a device sends the ORGANIZATION's name or the
-- deployment's address decides whether it can reach the folded enrolment path at all — and no measurement on
-- this side could answer it.
--
-- ★ AND THIS IS A SEPARATE FILE FOR THE REASON 043 GIVES. The columns were first appended to the 043 helper,
-- whose file this deployment has already applied: nothing would have run, every write would have been dropped
-- with "column does not exist", and the signals would have read as "no device reported". An applied migration
-- is history; new facts need new files.
ALTER TABLE observed_steer_exclusions
  ADD COLUMN IF NOT EXISTS interception_refusals jsonb NOT NULL DEFAULT '[]';
ALTER TABLE observed_steer_exclusions
  ADD COLUMN IF NOT EXISTS transport_server_name_sent text NOT NULL DEFAULT '';
