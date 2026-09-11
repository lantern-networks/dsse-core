CREATE TABLE IF NOT EXISTS workload_attestation_nonces (
  tenant_id text NOT NULL,
  nonce_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, nonce_hash)
);

CREATE INDEX IF NOT EXISTS workload_attestation_nonces_expires_idx ON workload_attestation_nonces (expires_at);
