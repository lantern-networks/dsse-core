# Recovering a paused audit archive

Use this maintenance procedure when an audit object was uploaded but the saved
chain head or hot-row deletion did not complete. It preserves every object and
hot row during repair. It does not make PostgreSQL and object storage atomic.
Only an operator with authority over the backing storage may perform it; this
is not a Console action and does not automatically create a Console audit event.
Record the operator, reason, time, backups, reviewed hashes, exact state change
and verification results in the protected maintenance record.

## Stop writers and establish the actual outcome

1. Stop **all** processes that can archive, prune, purge or update the relevant
   chain state, including standby processes that could become leader. Disable
   automatic restarts for the maintenance window. A local mutex or the absence
   of a current leader is insufficient. Leave writers stopped until verification
   is complete. Do not shorten retention or release a legal hold to make repair
   easier.
2. Back up the complete `audit_chain` payload, hot rows, object listing and exact
   compressed object bytes/version identifiers. Preserve unrelated tenant heads.
   Use the configured storage namespace; do not assume the default schema or
   file path. Do not copy credentials or audit contents into a public report.
3. Read the head from persistent storage, not a process cache. In PostgreSQL it
   is the `cp_state_blobs` row whose `store_key` is `audit_chain`; its `payload`
   is UTF-8 JSON stored as `bytea`. A file-backed store uses its configured JSON
   snapshot. `seq` is the **next** sequence number, not the last object's number.
4. Download and fully decompress the listed segments, checking gzip completion,
   the first-line `_audit_chain.seq` and `prev`, and SHA-256 of the **compressed**
   bytes. Sequences must start at zero with an empty previous hash and continue
   without gaps or forks. Every `prev` must equal the preceding compressed hash.
   The object at `saved seq - 1` must match the saved `last_hash`. Check the
   uploaded object's key/hash against the failed attempt's protected records.
   Inspect the event payloads and retained hot rows as well. A valid linked list
   or matching object count alone is not a trusted history or completeness proof.

| Persistent outcome | Action |
|---|---|
| Head and objects agree; shared PostgreSQL hot rows were deleted | The transaction committed. Do not advance the head again. Recreate the stopped process and verify before resuming. |
| Head and objects agree; hot rows remain | Keep the hot rows. A file-backed head can have saved before the SQL deletion failed. Resume only after reconciliation; a later sweep may archive duplicates. |
| Exactly one verified object extends the saved head; hot rows remain | Adopt that object's hash as the new head using the guarded procedure below. Keep all hot rows and objects. |
| Unreadable/missing established head, unknown origin, missing objects, forks, changed bytes, or more than one unexplained extension | Keep writers stopped. Restore or reconcile from independently trusted backups and storage versions. Do not infer a new head from the object count. This procedure does not resolve that ambiguity. |

An absent row after a failed first archive is not sufficient proof of a new
history: it can also mean lost state. Establish the original empty baseline and
every affected tenant from trusted evidence before restoring it. Never create
an empty snapshot merely to bypass the pause.

## Adopt one verified extension

Let the saved next sequence be `N`. The reviewed extra segment must have sequence
`N`, previous hash equal to the saved `last_hash`, and compressed SHA-256 `H`.
The replacement head is `{ "seq": N + 1, "last_hash": H }`. Change only this
tenant. Do not delete the extra object (it may be under WORM retention), delete
hot rows, renumber objects or reset the chain.

For PostgreSQL, use bound parameters in the following statement, inside a
maintenance transaction with short lock/statement timeouts. `$1` is the tenant,
`$2` is the hex encoding of the **complete backed-up payload**, `$3` is `N + 1`
and `$4` is the reviewed lowercase SHA-256 `H`. The exact-byte comparison rejects
a stale repair even if only another tenant changed. The SQL checks are additional
guards; they cannot validate an external object or replace the inspection above.

```sql
UPDATE cp_state_blobs
SET payload = convert_to(jsonb_set(convert_from(payload, 'UTF8')::jsonb,
    ARRAY[$1::text], jsonb_build_object('seq', $3::integer, 'last_hash', $4::text))::text, 'UTF8'),
    updated_at = now()
WHERE store_key = 'audit_chain'
  AND payload = decode($2::text, 'hex')
  AND jsonb_typeof(convert_from(payload, 'UTF8')::jsonb) = 'object'
  AND $3::integer = COALESCE((convert_from(payload, 'UTF8')::jsonb -> $1::text ->> 'seq')::integer, 0) + 1
  AND $4::text ~ '^[0-9a-f]{64}$'
RETURNING encode(payload, 'hex');
```

Require exactly one returned row. Compare the returned complete snapshot with
the backup: only the selected tenant's head may change. Commit only after that
comparison. Zero rows or an error means rollback and re-inspection; do not retry
with a newly read payload without reviewing it. If commit acknowledgement is
lost, reconnect and compare the actual saved state with both reviewed snapshots.
Do not apply the increment a second time.

For a file-backed store, with **all writers still stopped**, compare the complete
file bytes with the backed-up version immediately before replacement. Prepare a
complete snapshot preserving every peer head and changing only the reviewed
tenant. Use durable atomic file replacement (write and fsync a temporary file in
the same directory, rename, then fsync that directory), preserving restrictive
ownership and permissions. A bind-mounted single file may not support replacement;
do not treat that failure as success. Re-read the actual file after any uncertain
write. Do not edit a live snapshot in place or remove it to clear the error.

## Verify and resume

Re-read the saved state through a fresh store/process; an old process deliberately
retains its reconciliation error. Confirm the repaired head matches the retained
object bytes and all peer heads remain intact. Use **Logs & Audit → Volume →
Verify chain** for the listed chain, while retaining the independent saved-head
comparison: the Console verification alone does not prove that comparison.

Resume one eligible sweep after the existing hold/retention checks permit it.
Confirm its new object links to the adopted hash, hot rows are deleted only after
successful persistence, and peer tenants remain unchanged. Keep the original
objects and the maintenance evidence. This conservative recovery can put the same
event in the adopted object and a later segment; account for that duplication
when consuming archived records. It deliberately favors preservation over manual
deletion of records whose commit outcome was uncertain.

Real object-store permissions, versioning, WORM behavior and recovery across a
regional outage must be exercised on the deployment. Local adapters cannot
establish those properties.
