CREATE TABLE IF NOT EXISTS non_human_identities (
  tenant_id text NOT NULL,
  nhi_id text NOT NULL,
  name text NOT NULL,
  nhi_type text NOT NULL,
  owner_user_id text NOT NULL,
  trust_domain text,
  issuer text,
  subject text,
  credential_type text,
  allowed_application_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  allowed_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_used_at timestamptz,
  expires_at timestamptz,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'expired', 'revoked')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, nhi_id)
);

CREATE INDEX IF NOT EXISTS non_human_identities_tenant_status_idx ON non_human_identities (tenant_id, status);

CREATE INDEX IF NOT EXISTS non_human_identities_owner_idx ON non_human_identities (tenant_id, owner_user_id);

CREATE INDEX IF NOT EXISTS non_human_identities_subject_idx ON non_human_identities (tenant_id, issuer, subject);
