# Offline grant-store downgrade

`dsse-grant-migrate` converts a version 2 or 3 grant snapshot to the legacy map format. **Every grant is revoked**, including previously active grants. It preserves rows, prior revocations and unknown fields. Older servers cannot enforce request-bound grants, so preserving active authorization during a downgrade is unsafe. Users must authenticate again.

This is an offline operator tool, not a rolling-upgrade mechanism. Restore endpoint connectivity first, stop all CP/Edge readers and writers, and disable automatic restarts/rollback. The `--writers-stopped` option records the operator's assertion; it does not discover or stop processes. An active writer could upgrade the document again after migration.

Build from the module root:

```sh
go build -o dsse-grant-migrate ./cmd/dsse-grant-migrate
```

For a JSON file, inspect first and record the returned source hash:

```sh
./dsse-grant-migrate --input grants.json
./dsse-grant-migrate --input grants.json --output grants.legacy.json \
  --apply --writers-stopped --expect-sha256 SOURCE_HASH
```

The original remains intact. The output must not exist and is created with mode 0600. With all writers still stopped, securely retain the original and atomically install the converted file at the configured grant-store path, preserving the service's required ownership. Do not restore an older backup over newer revocations.

For the shared PostgreSQL `cp_state_blobs` row with `store_key='grants'`, provide the DSN through `DSSE_GRANT_MIGRATION_DSN` using your secret-management mechanism. Use the deployment's existing TLS verification settings; do not disable TLS verification for a remote database.

```sh
./dsse-grant-migrate --postgres
./dsse-grant-migrate --postgres --apply --writers-stopped \
  --expect-sha256 SOURCE_HASH --backup grants.before-downgrade.json
```

The tool locks the row, verifies its exact hash, writes and syncs a private backup, then conditionally updates and commits that row. It does not modify any other state or run database migrations. A changed snapshot, unsupported schema, invalid grant, or existing output/backup file aborts the operation. Database errors are reported without printing the DSN, grant contents or identity claims.

If commit acknowledgement is lost, the database may already contain the revoked legacy snapshot. Run read-only inspection and compare the output hash; do not blindly repeat the write or restore the backup. Keep all nodes stopped until the database result is known. Start the coordinated older server version only after verifying the legacy snapshot and retaining the backup. Newer request-bound semantics are not available in that older version.

The file conversion and PostgreSQL path have local automated tests. This does not certify a particular deployment's failover, restore or mixed-version behavior. There is no AWS dependency.
