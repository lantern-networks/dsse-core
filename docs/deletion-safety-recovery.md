# Deletion after restart or leadership change

Retention pruning and tenant erasure start paused after **every process start
or control-plane leadership change**, including the first installation. Reads
and saving protective settings remain available. This prevents an unsuccessful
hold or indefinite-retention request, retained only in the previous process,
from being forgotten when a successor starts deleting logs.

The `legal_hold` snapshot carries a version 3 `deletion_permit` naming one
process and one leader term. The running process generates a new random identity
at startup. The deletion guard checks the permit with the latest policy in the
deletion transaction. A missing, malformed, previous-process or previous-term
permit cannot authorize deletion. Successful election and elapsed time never
clear this restriction. The permit does not override holds, pending local
requests, retention settings, or interrupted-erasure markers.

Upgrade **all** readers and writers of this authority before using version 3.
Earlier readers reject it; do not strip the permit or downgrade its version.
Ordinary hold changes and erasure-marker changes preserve the permit. A CP using
PostgreSQL must keep both hold and retention stores on that same shared
authority. Explicit file overrides on that CP leave deletion paused. Separate
node-local files cannot provide fleet-wide protection.

## Reconcile before authorizing the current process

This is a restricted maintenance procedure, not a Console action or automatic
failover recovery. Its cost is that log storage can continue to grow while
deletion is paused. Monitor capacity and keep the pause if evidence is missing.

1. Stop old writers and outstanding deletion work; prevent them from restarting.
   Keep the intended successor running, with administration writes quiesced.
   Confirm its deletion guard is refusing work. A restart of that successor
   changes its identity and invalidates the authorization prepared below.
2. Reconcile unsuccessful and unconfirmed preservation requests against operator
   records, responses and audit records from the previous writer. A missing
   pending list on the successor is **not** evidence that no requests existed.
   Reapply and verify required holds/indefinite retention. If records are
   incomplete, keep deletion paused; do not authorize based on a guess.
3. Recover interrupted erasures separately using
   [tenant-erasure-recovery.md](tenant-erasure-recovery.md). Preserve other
   tenants' holds, markers and retention settings. Inspect archive failures
   using the existing archive-reconciliation procedure before resuming sweeps.
4. Obtain `process` and `term` from the intended node's current `deletion paused`
   log/error. The startup log also gives `process`. PostgreSQL requires a positive
   decimal leader term; a single-process file deployment uses `local`. A stale
   value fails closed. These are identities, not an authorization secret.
5. Capture the **entire** current `legal_hold` payload and a restricted backup.
   Decode it with the current version. For a legacy hold array, construct
   `{"version":3,"holds":<the exact existing array>,"erasures":{},"deletion_permit":...}`.
   For version 2/3, preserve every hold and erasure, change only `version` to 3
   and `deletion_permit` to `{"process":<current process>,"term":<current term>}`.
   Never substitute an empty state for an absent or unreadable established row.
   A genuinely new installation must first persist and verify its initial
   protection configuration; it receives no automatic deletion permit.
6. With PostgreSQL, bind `expected_hex` and `replacement_hex` to those complete
   old/new payloads. Execute in a transaction, require **exactly one** updated
   row, read it back and commit. A zero-row result requires rollback and renewed
   inspection; do not overwrite a concurrent change.

```sql
-- deletion-safety-recovery-cas-begin
UPDATE cp_state_blobs
SET payload = decode(:'replacement_hex', 'hex'), updated_at = now()
WHERE store_key = 'legal_hold'
  AND payload = decode(:'expected_hex', 'hex');
-- deletion-safety-recovery-cas-end
```

   In single-process file mode, quiesce administrative writers, compare the
   complete original bytes, and replace only that permit/version using a synced
   temporary file, atomic rename and directory sync. Preserve permissions.
   The running owner accepts this change on its next guarded deletion only if
   all confirmed holds/erasure markers match its in-memory state. An external
   policy change instead keeps deletion paused. Do not share the file between
   processes or edit it in place. A concurrent ordinary save can invalidate
   the permit, requiring a fresh inspection; it cannot authorize a successor.
7. Verify persisted bytes and the current process/term; inspect a guarded retry
   and its actual retained/deleted resources. Record operator, reason, source
   records, before/after hashes and outcome in the restricted maintenance
   record. This direct repair is not an AdminConsole audit event. Keep any
   unresolved request protected and check the normal operation's audit record.

File calls already executing in the OS cannot be canceled merely by canceling
an HTTP request. Do not release their exclusion or authorize a replacement until
their termination is established. This permit is not a distributed file-I/O
lock and does not establish independent Edge/region delivery of protection.
