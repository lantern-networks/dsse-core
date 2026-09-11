DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'domain_event_outbox_stream_check'
      AND conrelid = 'domain_event_outbox'::regclass
  ) THEN
    ALTER TABLE domain_event_outbox
      ADD CONSTRAINT domain_event_outbox_stream_check CHECK (stream IN ('authentication_events', 'break_glass_events', 'device_events', 'agent_update_events', 'human_approval_events', 'delegated_access_grants', 'tool_call_events', 'inspection_events', 'access_logs', 'decision_traces', 'connector_logs'));
  END IF;
END
$$;
