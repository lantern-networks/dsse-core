-- Global generations prevent stale writes even after deletion and recreation.
CREATE SEQUENCE IF NOT EXISTS admin_local_credentials_revision_seq AS bigint;
ALTER TABLE admin_local_credentials
    ADD COLUMN IF NOT EXISTS revision bigint NOT NULL
    DEFAULT nextval('admin_local_credentials_revision_seq') CHECK (revision > 0);
