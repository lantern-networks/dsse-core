-- First-party admin credentials (invite -> activation -> password + TOTP). Durable store on the control
-- plane so SaaS-issued admin accounts survive a control-plane restart (the in-memory store loses them).
CREATE TABLE IF NOT EXISTS admin_local_credentials (
  email                 text PRIMARY KEY,
  principal_id          text NOT NULL,
  tenant_id             text NOT NULL,
  roles                 jsonb NOT NULL DEFAULT '[]',
  status                text NOT NULL,
  password_hash         text NOT NULL DEFAULT '',
  totp_secret           text NOT NULL DEFAULT '',
  totp_enrolled         boolean NOT NULL DEFAULT false,
  recovery_code_hashes  jsonb NOT NULL DEFAULT '[]',
  failed_attempts       integer NOT NULL DEFAULT 0,
  locked_until          timestamptz,
  activation_token_hash text NOT NULL DEFAULT '',
  activation_expires_at timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);
