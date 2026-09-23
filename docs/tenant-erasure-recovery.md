# Interrupted tenant erasure

Tenant erasure is a sequence across stores, files and possibly separate database
pools. It is not one transaction and does not roll back data already removed.
The result reports partial failures and the remaining footprint. Fleet delivery
markers are retained when preceding erasure or completion recording fails.

Before touching a store, the erasing node saves an operation ID, node name and
start time in the `legal_hold` snapshot. This orders erasure against hold changes:

* A hold accepted first prevents erasure from starting.
* While erasure is recorded, both hold activation and release for that tenant
  are refused. A refused activation is not a successfully saved hold. Retry only
  after the erasure has ended and its result has been reconciled.
* Ordinary retention/archive deletion and a second erasure cannot bypass the
  marker. Only the operation that created it can perform its guarded steps.
* Request cancellation cannot clear the marker until the resource calls have
  returned. SQL session or leadership loss cannot remove the persisted marker.
* The marker has no expiry. A partial failure, process crash or unconfirmed completion save can
  leave it requiring offline recovery. Leadership transfer alone is insufficient
  evidence that a file or independent database operation has stopped.

This exclusion covers writers using the same PostgreSQL protection authority,
or one process owning a durable file store. It is not cross-region hold delivery.
Independent local files on different nodes do not provide a shared authority.
In-memory stores do not survive process restart. Never operate multiple processes
against the same file store. Separate fleet protection/delivery verification is
required before relying on a deployment-wide hold.

## Snapshot compatibility

The first erasure writes version 2:

```json
{"version":2,"holds":[],"erasures":{"tenant-id":{"id":"0123456789abcdef0123456789abcdef","node":"node-name","started_at":"2026-09-23T00:00:00Z"}}}
```

The existing hold array is still readable before migration. Version 2 remains
version 2 after the last erasure marker is removed. Upgrade every reader/writer
of that authority before performing erasure. Older array-only readers reject
version 2; do not convert it back, remove unknown fields, or restore a stale
snapshot to permit an old binary to run.

## Offline recovery

1. Stop every process that can erase, prune, archive or write protection state
   for the affected tenant/authority. Disable automatic restarts and drain or
   terminate outstanding file/object/database work, including the previous
   leader's work. Verify it cannot resume. If this cannot be established, keep
   the marker and stay stopped.
2. Preserve the original snapshot bytes, operation ID, node, time, partial
   response, resource inventories and relevant logs in a restricted incident
   record. Inspect remaining stores and fleet delivery markers. A missing or
   malformed snapshot requires restoration from trusted evidence; do not replace
   it with an empty state. The procedure below applies only to a known version 2
   snapshot and the exact interrupted operation.
3. Remove only that operation's marker. Keep all hold records, other operation
   markers and the version. For PostgreSQL, bind `expected_hex` to the captured
   payload bytes (hex), and `tenant`/`operation_id` to the inspected values. Run
   the following in a transaction and require exactly one affected row. Zero
   rows means the snapshot changed or the operation did not match: roll back
   and investigate. These are psql variables, not literal example identifiers.

```sql
-- tenant-erasure-recovery-cas-begin
WITH expected AS (
  SELECT decode(:'expected_hex', 'hex') AS raw
), inspected AS (
  SELECT raw, convert_from(raw, 'UTF8')::jsonb AS doc FROM expected
)
UPDATE cp_state_blobs AS state
SET payload = convert_to((inspected.doc #- ARRAY['erasures', :'tenant'])::text, 'UTF8'),
    updated_at = now()
FROM inspected
WHERE state.store_key = 'legal_hold'
  AND state.payload = inspected.raw
  AND inspected.doc->>'version' = '2'
  AND inspected.doc #>> ARRAY['erasures', :'tenant', 'id'] = :'operation_id';
-- tenant-erasure-recovery-cas-end
```

   For a file store, while its sole owner is stopped, make the equivalent change
   to the captured version 2 JSON using the exact tenant/operation ID. Verify
   the original bytes are still unchanged, then write through a temporary file,
   sync it, atomically replace the original and sync its directory. Keep the
   original permissions and the restricted backup. Do not edit the live file
   in place or clear other tenants' markers.
4. Read back with the current binary's store decoder; confirm the target marker
   alone is absent and all other protection is unchanged. Record before/after
   hashes, operator, reason and resource reconciliation. This is an offline
   maintenance action, not an AdminConsole audit event.
5. Restart current-version writers and inspect the footprint. If preservation is
   now required, save and verify a hold before enabling deletion again. Otherwise
   retry the existing erasure operation, inspect its partial/full result and
   remaining footprint, and verify fleet delivery markers. Retrying does not
   restore data already erased. Unreachable nodes and external archives remain
   explicit deployment follow-up items.
