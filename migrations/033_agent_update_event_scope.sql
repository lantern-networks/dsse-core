-- 033: an agent update event is unique PER DEVICE, not globally.
--
-- The id in an agent_update_event is chosen by the endpoint that reports it. With event_id as the primary key
-- one device could suppress another's event — across tenants — by sending the same string, and the upsert that
-- used to sit behind it would rewrite that row's tenant_id, device_id and payload. Both halves are wrong for
-- the same reason: a client-chosen identifier is only meaningful beside the device that chose it.
--
-- The insert path now uses ON CONFLICT DO NOTHING, so the remaining risk was a legitimate event being silently
-- dropped because a different device had already used its id — answered 202, and the device deletes its only
-- copy.
--
-- Written to be safe on a table that already exists and may already hold rows: duplicates across (tenant,
-- device, event) cannot exist today because event_id was globally unique, so the new constraint can be added
-- without a de-duplication pass.
ALTER TABLE agent_update_events DROP CONSTRAINT IF EXISTS agent_update_events_pkey;
ALTER TABLE agent_update_events
  ADD CONSTRAINT agent_update_events_scope_pkey PRIMARY KEY (tenant_id, device_id, event_id);

-- The same reasoning applies to agent status events, which carry a client-chosen id in exactly the same way.
ALTER TABLE agent_status_events DROP CONSTRAINT IF EXISTS agent_status_events_pkey;
ALTER TABLE agent_status_events
  ADD CONSTRAINT agent_status_events_scope_pkey PRIMARY KEY (tenant_id, device_id, agent_status_id);
