ALTER TABLE agent_status_events DROP CONSTRAINT agent_status_events_device_trust_level_check;
ALTER TABLE agent_status_events ADD CONSTRAINT agent_status_events_device_trust_level_check CHECK (device_trust_level IN ('managed', 'unmanaged', 'unknown', 'noncompliant'));
