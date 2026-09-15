-- Preserve consumed TOTP steps across restarts. Existing rows have no previous
-- counter history; enforcement begins with their first successful login after upgrade.
ALTER TABLE admin_local_credentials
  ADD COLUMN IF NOT EXISTS last_totp_counter bigint NOT NULL DEFAULT 0
  CHECK (last_totp_counter >= 0);
