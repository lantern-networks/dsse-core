ALTER TABLE admin_tenant_models ADD COLUMN IF NOT EXISTS is_operator boolean NOT NULL DEFAULT false;
