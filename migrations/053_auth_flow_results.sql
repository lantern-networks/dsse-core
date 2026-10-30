-- Terminal results belong to one held flow. Keep each request in its own row
-- so a busy tenant cannot lock or exhaust the result capacity of its peers.
CREATE TABLE IF NOT EXISTS auth_flow_results (
    request_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    device_id text NOT NULL,
    os_principal text NOT NULL,
    os_session text NOT NULL,
    result text NOT NULL CHECK (result IN ('resumed', 'not_resumed')),
    final_at bigint NOT NULL,
    expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_flow_results_tenant_expiry_idx ON auth_flow_results (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS auth_flow_results_expiry_idx ON auth_flow_results (expires_at);
