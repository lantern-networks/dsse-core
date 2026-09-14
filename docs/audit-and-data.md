# Audit logs and data handling

Use this guide to locate evidence and define a deployment's data lifecycle. It describes
the current implementation, which may change; it is not a compliance certification.
See [Operations](operations.md) for state and backup preparation.

## What the records contain

| Record | Typical use and potentially identifying context |
|---|---|
| Audit | Administrative action, actor, organization, resource, time, and outcome |
| Access | Traffic decision, policy, user/device, application, source and destination context |
| Inspection / DLP | Detection type/count, action, rule, destination, and source identity context |
| Device state / configuration generations | Endpoint state and configuration distribution evidence |
| Approval / delegated grant | Who requested, approved, or exercised an access grant and its scope |
| Service / endpoint logs | Startup, TLS, delivery errors, process diagnostics, and operational identifiers |

Fields depend on the stream and execution path. The DLP finding writer does not store
the matched body value, but this does **not** make all records anonymous or safe to post
publicly. User names, email/account identifiers, IPs, hostnames, device IDs, policy text,
and error details can reveal customer information. Inspect actual samples before sharing.
Packet captures and operator-enabled debug output require their own review.

Configuration is also data: IdP client secrets, CA private keys, enrolment material, API
tokens, custom DLP keywords, and allowlist values need restricted access and backup
handling. EDM datasets retain hashes after submission; see [DLP](dlp.md) and [PKI](pki.md).

## Find and correlate an event

1. Enter the correct organization and open **Logs & Audit**. Confirm the time range and
   timezone; Console log timestamps follow the organization's timezone.
2. Choose the stream and filter by time, device/user, policy, decision, or other available
   fields. Preserve correlation identifiers and the relevant configuration revision.
3. Compare the endpoint's outcome, the Edge decision, and control-plane delivery. An
   empty view alone does not prove that no request occurred.
4. When exporting, verify the job's final state and the downloaded artifact before
   treating it as evidence. Keep its tenant, filters, time interval, and access restrictions.

The Console routes `audit`, `access`, `device_state`, `inspection_events`, and
`config_generations` queries to the control plane; other streams can be read from the
Edge. Store contents, recent-window limits, and delivery delay can therefore differ.
Access decisions carry decision-trace fields; there is no separate current decision-trace
stream. DLP Findings is not a record of every scanned or skipped request.

The default `-access-log-all=true` records routine egress decisions as well as policy
actions. Selective logging changes this coverage. A DLP finding write is best effort:
logging failure does not turn an otherwise permitted request into a denial.

## Retention is specific to each store

The following are **binary flag defaults**, not a readback of a running deployment.
Generated configuration, runtime overrides, and storage settings can change them.

| PostgreSQL pruner setting | Default |
|---|---|
| `-retention-poll` | Every hour; zero disables the pruner |
| `-hot-events-retention` | 720 hours (30 days) |
| `-hot-events-retention-overrides` | `audit`, `human_approval_events`, `delegated_access_grants`: 8,760 hours (365 days) |
| `-outbox-published-retention` | 720 hours (30 days) |
| `-outbox-dead-retention` | 336 hours (14 days) |
| `-audit-cold-retention` | 8,760 hours of requested object retention after archival, when configured |

The pruner starts where PostgreSQL is configured and performs work on the control-plane
leader. Setup failure is logged and startup can continue without pruning. Hot-event
retention precedence is **Console override, then per-stream startup override, then global
default**. Zero keeps that stream indefinitely. Clearing a Console override restores the
startup setting; it does not erase records immediately. Enter whole days (0–106751);
an omitted or null day count is rejected unless clearing an override.

If persisted retention overrides cannot be read or validated, this process pauses the
retention sweep, including its outbox cleanup. It does not substitute default TTLs or
accept changes over the unreadable snapshot. The Console reports an unavailable state
and offers retry instead of showing empty overrides. Repair the backing data and reload
the store (normally by restarting the affected process); retrying the page alone does not
clear a startup load failure. A missing initial snapshot or an empty object is valid and
uses startup defaults. This protection applies to this pruner, not external lifecycle jobs
or explicit tenant erasure. Preserve storage capacity while pruning is paused.

Console per-stream retention changes affect the **whole node**, not just the selected
customer, and require the deployment-wide administration boundary. Do not promise a
customer-specific TTL from this control. Tenant legal holds skip that tenant's hot-event
pruning while active. This is not a universal hold on every copy: the outbox cleanup loop
is separate, and other stores and backups need their own lifecycle controls.

With a usable cold archive, aged hot events are written as compressed NDJSON segments
before deletion from PostgreSQL. A failed archive write leaves those rows for retry.
Without a cold archive, the same hot-event path deletes aged rows. Cold-archive setup
failure can leave the deployment running without that tier; check startup logs and a
sample archived object before relying on it. Requested audit object retention requires
a compatible, correctly configured object-lock bucket. Its presence in a flag is not
proof that every log is immutable or that a retention obligation is met.

| Other copy | What must be managed separately |
|---|---|
| Edge JSONL files and rotated backups | Local rotation flags, disk use, permissions, and collection |
| Local inspection/event state and shipping spool | Persistence configuration, restart behavior, pending deliveries |
| ClickHouse projections | Their schema, TTL, and deletion process |
| Cold archive and export artifacts | Bucket lifecycle, locks, access, and downloaded copies |
| Database/volume backups | Backup retention, encryption keys, restore access, and expiry |
| OS logs and endpoint diagnostic bundles | Host policy and support-sharing lifecycle |

Changing hot retention or deleting a Console record does not certify deletion from this
entire set. Record the effective configuration and test a sample record through its
actual lifecycle before making a deletion or preservation claim.

## Delivery problems and access

Monitor pending, publishing, published, and dead outbox states where used. Published and
dead rows have separate cleanup periods; pending/publishing rows are not pruned by that
cleanup. A dead row represents failed delivery, not successful retention. Investigate the
destination and error before an authorized replay, then verify the received event.

Log reads and exports require their respective permissions and tenant scope. Analyst
and auditor roles can create exports; "read-oriented" does not mean data cannot leave
through an export. Operator access to customer records also needs customer delegation.
See [Administration](administration.md) for these boundaries.

For a support report, share the smallest relevant time window, configuration revision,
and sanitized identifiers. Remove cookies, bearer tokens, enrolment links, secrets, raw
payloads, and customer-specific names not needed to reproduce the problem. Keep an
unredacted original only in the authorized private evidence store. Use the private
reporting channel in [SECURITY.md](../SECURITY.md) for vulnerabilities.

Implementation: [pruner](../cmd/dsse-edge/retention_pruner.go),
[retention routes](../cmd/dsse-edge/admin_logs_retention_routes.go),
[Console routing](../console/logsaudit.js), and [flags](../cmd/dsse-edge/main.go).

### PostgreSQL regional log schema

The PostgreSQL hot store requires migration
`050_hot_events_region.sql` for regional log ingestion and filtering. Component
startup applies it when migrations are enabled. If you manage migrations separately,
apply it before starting the updated service. Existing log rows are preserved and
receive an empty region value; the migration does not infer their original region.
New records carry the region supplied by the event. Verify ingestion and a regional
search after upgrading, and check service logs for ingestion errors.

### When legal-hold state cannot be loaded

A storage read error or invalid legal-hold snapshot pauses retention pruning and
refuses tenant deletion, purge, and hold changes. The Console shows a load error
with Retry instead of treating the hold as off. Repair the storage or restore a
verified snapshot, then restart the affected service so it can load the complete
state. Refreshing the page alone does not clear the protection. Do not replace an
unreadable snapshot with an empty list to regain access: that would discard holds.

The same protection applies when this node receives a signed tenant-erasure order.
An active hold or unavailable hold state stops the shared purge operation before
any store is erased. The order remains outstanding; the service reports an
incomplete erasure in its logs and retries when the bundle is applied again.
Release the hold explicitly, or repair the state and restart, before retrying.
A signature authorizes the order but does not override local preservation.

After a failed hold change, the Console fetches the current status again. If that
read also fails, it shows an error rather than leaving the old status and controls.

A failed hold change records an error through the normal HTTP audit path, provided
the audit writer is available. Audit outbox health describes delivery processing;
it is not proof that every primary audit-file write succeeded. Inspect service
logs for `admin_audit_write_failed` when investigating missing audit records.

### Observing audit-file write failures

Deployment-wide administrators can read `GET /admin/audit-writer/health` with
`admin.logs.read`; customer-scoped requests, including an operator acting within a
customer, cannot read this node-wide diagnostic. Logs & Audit displays the same
observation and offers Retry if it cannot be fetched. The endpoint is independent
of the optional embedded outbox-admin endpoints.

The common writer observes appends to the logical `audit.log.jsonl` stream, including
direct worker audit writes. `primary_failures` covers encoding, opening, writing and
rotation failures. `hook_failures` separately counts post-write append-hook failures:
the primary file write has completed before the hook runs. These are not outbox
backlog counts, and outbox-insert failures after `Append` returns are not measured
by this monitor.

`unknown` means no completed append has been observed; `unavailable` means no writer
is configured. Any observed primary failure keeps status `degraded`, even after
later successful writes. Counters and fixed failure-phase/timestamp fields carry no
tenant identifiers, event contents, filesystem paths or raw error messages.

These are in-memory observations for this Writer instance, normally its process
lifetime. Restart or recreation resets them to unknown; it does not prove that a
missing audit record was recovered. An append still in progress is not yet counted.
This is not a storage probe, a stalled-write watchdog, a fleet aggregate, an fsync
guarantee or a completeness claim. Rotation failure may occur after bytes were
written, so a failure count is not an exact count of missing records. Preserve and
investigate service logs before restarting a failed writer. Reading health performs
no audit write of its own and cannot repair or clear an earlier failure.

### Records without a region

A regional search excludes records whose stored region is unknown, including older
PostgreSQL rows upgraded without a region. A zero-result regional search therefore
does not prove that no relevant older records exist.

For regional log queries, `region_coverage` reports an `unknown_region_count` when
the backend can count it. PostgreSQL counts unknown-region records in the same tenant,
stream, time range, text query and remaining filters, independent of pagination.
The count is a separate live query, not a transactionally frozen export snapshot.
Unsupported backends or count failures return `status: "unavailable"` and a null
count. The Console displays that uncertainty instead of zero.

The synchronous preview export includes `X-DSSE-Region-Coverage`,
`X-DSSE-Region-Notice`, and, when available, `X-DSSE-Unknown-Region-Count` headers.
These headers are not embedded in exported log rows.

New asynchronous regional exports persist `metadata.region_coverage` on the completed
job and embed the same JSON in the gzip file's Comment header. The manifest identifies
`dsse.export-region-coverage.v1`, states that unknown-region records are excluded,
and records the available count or unavailable/null, the check time, and
`snapshot_consistent: false`. The job's existing filters and time range retain the
full request scope. The count is a separate live query, not proof of a frozen snapshot
or of complete retention across all stores.

The gzip checksum covers the header and the original NDJSON together. No annotation
rows are inserted, and an empty export still carries its header. Download tokens
carry the same compressed bytes. Both built-in generated-file stores support this;
a regional export fails if its object store cannot preserve the header. Non-regional
exports keep their existing format. Existing artifacts are not retroactively changed;
missing coverage in older jobs is unknown, never zero.

Keep the original `.gz` file when sharing evidence: decompression or recompression
can discard the Comment header. Many gzip tools do not display it automatically.
For example, save this as `read-export-note.go` and run
`go run read-export-note.go export.ndjson.gz` to inspect the note without altering logs:

```go
package main
import ("compress/gzip"; "fmt"; "os")
func main() {
    if len(os.Args) != 2 { panic("provide one .gz export") }
    f, err := os.Open(os.Args[1]); if err != nil { panic(err) }; defer f.Close()
    r, err := gzip.NewReader(f); if err != nil { panic(err) }; defer r.Close()
    if r.Comment == "" { fmt.Println("No embedded coverage information"); return }
    fmt.Println(r.Comment)
}
```

The Console export list also displays regional coverage or explicitly marks it
unavailable, including for older jobs. A completed status means the requested export
finished; it does not imply that unknown-region records were included.

## Archive chain verification scope

The Console chain verifier checks the audit segments returned by the archive listing.
It requires a valid chain header, contiguous sequence numbers starting at zero, matching
previous-object hashes, and readable gzip data through the trailer. Missing or malformed
headers and gzip checksum/truncation failures are verification failures. An empty listing
is reported as **no segments to verify**, not an intact archive.

A successful result (`links_verified`, `scope: listed_segments_only`) confirms these checks
on the listed objects. It does not compare against an independently trusted final hash or
expected segment count. Removing the last segment(s), rewriting a complete internally
consistent chain, or an incomplete archive listing can escape detection. Retain independent
checkpoints and verify storage retention controls before relying on completeness claims.
With the remaining headers unchanged, removing a first or intermediate segment breaks
sequence continuity. Rewriting an intermediate segment without updating its successor
breaks the successor's hash reference. However, rewriting the final segment as valid gzip
while retaining its header is also undetectable here: there is no successor to check its
new object hash against. A trusted terminal hash is needed to cover that case.

A reported failure is not by itself proof of malicious tampering; incomplete writes or a
legacy unchained segment also fail verification.

Audit writer health displays the browser retrieval time and does not refresh automatically.
Its failure counters describe append operations, not a count of missing audit records;
rotation can fail after record bytes have already been written.

## Archive write failures and hot-row deletion

Tiering locks the selected hot rows in a database transaction while uploading the
segment. A scan or row-read failure aborts the attempt without publishing or deleting
rows. After upload, only the selected event IDs may be deleted; older rows arriving
during upload remain for a later sweep. The upload holds row locks, so slow archive
storage can delay updates to those rows.

For chained audit segments, chain state must save successfully before hot-row deletion.
A state-save error leaves hot rows in place and pauses further chained writes in this
process. Each attempt checks the listed archive count against the saved chain position;
a mismatch also pauses writes, including after a restart. This is a reconciliation guard,
not a transactional or completeness guarantee across the database and archive backend.
Diagnostics distinguish `archive listing failed` (the listing could not be obtained;
the next sweep retries) from `archive count mismatch` (a successful listing disagreed
with the saved position). A mismatch includes the tenant and expected/actual counts.
Neither message alone establishes malicious tampering.
Repair requires inspecting the saved head and archived objects together. Do not reset the
chain to zero or delete retained hot rows to clear the error.

Segment names include creation time, sequence and content hash so a retry after a failed
delete does not overwrite a preceding chained segment. Upload followed by delete failure
can leave duplicate audit records in multiple valid segments. An ambiguous upload or
state-save outcome may require operator reconciliation. Writes are serialized in one
process; cross-process writers and leader changes still require separate coordination.

When a runtime override store is configured, the pruner can apply Console overrides even
if startup hot-event TTLs are all zero. A zero polling interval still disables the pruner.

## Export form dates and format

The asynchronous export API supports NDJSON; the Console offers that format only.
Both a start and an end date are required. Console date selections use the operator's
local calendar: start is local midnight, and the selected end date includes its entire
day, including on daylight-saving transitions. The API receives explicit timestamps
and rejects an end before the start before submitting work. Equal timestamps remain
valid for API clients requesting one instant.

Invalid or missing dates remain in the form with an error so they can be corrected.
Failed export requests receive error audit outcomes. Job-state colors use explicit
outcomes; an unknown or incomplete status is not evidence of a completed export.

### Enrolment token state persistence

For the file/blob-backed enrolment token store, issuance, consumption, revocation and tenant removal publish their new in-memory state only after saving succeeds. A save failure stops further issuance and token verification/spending in that process; the AdminConsole token routes report the store as unavailable. A revocation whose save fails returns 503 and is audited as an error. Tenant erasure reports a failure instead of counting unsaved token removals as erased.

Treat an unavailable store as requiring investigation. A storage error may mean nothing was saved, or that saving completed but its acknowledgement was lost. Reconcile the saved state and the failed operation before restarting; a restart alone does not establish that a failed revocation was persisted. Existing successfully issued device certificates are not revoked by this token-store safeguard. The in-memory store without a persister remains non-durable. A persister that explicitly reports `ErrSavedWithoutAtomicity` retains its existing saved-but-not-atomic behavior and warning.
