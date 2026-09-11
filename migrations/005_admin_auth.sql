CREATE TABLE IF NOT EXISTS admin_principals (
  tenant_id text NOT NULL,
  admin_principal_id text NOT NULL,
  idp_id text NOT NULL,
  subject text NOT NULL,
  email text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
  created_at timestamptz NOT NULL,
  last_login_at timestamptz,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, admin_principal_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_principals_subject_unique_idx ON admin_principals (tenant_id, idp_id, subject);

CREATE INDEX IF NOT EXISTS admin_principals_tenant_status_idx ON admin_principals (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS admin_sessions (
  tenant_id text NOT NULL,
  session_id text NOT NULL,
  admin_principal_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_active_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, session_id)
);

CREATE INDEX IF NOT EXISTS admin_sessions_principal_idx ON admin_sessions (tenant_id, admin_principal_id, created_at DESC);

CREATE INDEX IF NOT EXISTS admin_sessions_status_expiry_idx ON admin_sessions (tenant_id, status, expires_at);

CREATE TABLE IF NOT EXISTS admin_api_tokens (
  tenant_id text NOT NULL,
  token_id text NOT NULL,
  token_hash text NOT NULL,
  created_by_admin_principal_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, token_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_api_tokens_hash_unique_idx ON admin_api_tokens (token_hash);

CREATE INDEX IF NOT EXISTS admin_api_tokens_tenant_status_idx ON admin_api_tokens (tenant_id, status, expires_at);
