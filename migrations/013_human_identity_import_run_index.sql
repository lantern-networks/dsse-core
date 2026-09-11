CREATE INDEX IF NOT EXISTS human_identities_import_run_idx ON human_identities (tenant_id, (metadata->>'import_run_id'));

CREATE INDEX IF NOT EXISTS human_identities_deactivated_import_run_idx ON human_identities (tenant_id, (metadata->>'deactivated_by_import_run_id'));
