-- Fence older writers that do not participate in credential generation checks.
-- This is compatibility enforcement, not authorization against a database owner.
CREATE OR REPLACE FUNCTION require_admin_credential_writer_protocol() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('dsse.credential_write_protocol', true) IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'administrator credential writer protocol is unsupported; upgrade all authentication authorities'
            USING ERRCODE = '55000';
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER admin_credential_writer_protocol
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON admin_local_credentials
    FOR EACH STATEMENT EXECUTE FUNCTION require_admin_credential_writer_protocol();
