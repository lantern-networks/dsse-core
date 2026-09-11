CREATE TABLE IF NOT EXISTS human_identities (
  tenant_id text NOT NULL,
  human_identity_id text NOT NULL,
  subject text NOT NULL,
  email text,
  display_name text,
  source text NOT NULL,
  department text,
  last_seen_at timestamptz,
  expires_at timestamptz,
  status text NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, human_identity_id)
);

CREATE INDEX IF NOT EXISTS human_identities_tenant_status_idx ON human_identities (tenant_id, status);

CREATE INDEX IF NOT EXISTS human_identities_subject_idx ON human_identities (tenant_id, subject);

CREATE INDEX IF NOT EXISTS human_identities_email_idx ON human_identities (tenant_id, email);
