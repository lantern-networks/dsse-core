-- Deployment-scoped archive failure and recovery transitions use the existing
-- signed domain-event outbox. Keep its database allowlist in sync with Go.
ALTER TABLE domain_event_outbox DROP CONSTRAINT IF EXISTS domain_event_outbox_stream_check;
ALTER TABLE domain_event_outbox ADD CONSTRAINT domain_event_outbox_stream_check
  CHECK (stream IN ('authentication_events', 'break_glass_events', 'device_events', 'agent_update_events', 'human_approval_events', 'delegated_access_grants', 'tool_call_events', 'inspection_events', 'access_logs', 'decision_traces', 'connector_logs', 'cold_archive_health_events'));
