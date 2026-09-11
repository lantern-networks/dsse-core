-- 034: a device that was TOLD to update and cannot is a fleet state an operator needs to see.
--
-- The endpoints now report a `refused` outcome — an artifact that will not stage, a manifest that will not
-- verify — and the CHECK constraint written for 019 does not list it, so every one of those rows was rejected
-- on the PostgreSQL backend. The devices most worth seeing were the ones that could not be recorded.
--
-- The senders map `refused` to `failed` for exactly this reason, with metadata.refused beside it. That mapping
-- stays (it is what an operator's success-rate reading means), and this makes the value itself storable so a
-- future sender does not have to lie about it.
ALTER TABLE agent_update_events DROP CONSTRAINT IF EXISTS agent_update_events_update_status_check;
ALTER TABLE agent_update_events
  ADD CONSTRAINT agent_update_events_update_status_check
  CHECK (update_status IN ('available', 'downloaded', 'installing', 'installed', 'failed', 'rolled_back', 'refused'));
