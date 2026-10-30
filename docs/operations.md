# Operations

Use this guide after [deployment verification and first use](after-verify.md). It describes
routine operation of an experimental lab; it does not establish availability targets,
production sizing, or a tested disaster-recovery procedure for your environment.

For CA structure, key custody, automatic certificate renewal, and the lifecycles
that still need operator action, see [PKI structure and lifecycle](pki.md).

## Keep a deployment record

Keep a private record of the source revision, image references or digests, agent versions,
topology, generated plan, node names, deployment directories, and Compose project names.
Record who holds the founding authority material and how to recover it. Store credentials
separately from ordinary maintenance notes. The generated directory, carry archives,
bootstrap output, and enrolment files contain sensitive material.

Use the selected revision's `dsse-install -plan ... -order` output as the topology's
command reference. Founding and joining regions may use different Compose project names.
Do not copy the founding node's `-p dsse` into commands for a joining region without checking.

## Routine checks

For the founding node, replace the directory with the actual generated directory:

```sh
export DSSE_DIR=/opt/dsse/region-a
cd "$DSSE_DIR"
docker compose -p dsse --env-file deployment.env ps -a
docker compose -p dsse --env-file deployment.env logs --tail=100
df -h "$DSSE_DIR"
```

`df` measures the filesystem containing that directory. Check the filesystems actually
holding database volumes and audit spools too. Successful initialization jobs may have
exited; long-running services should remain healthy. Logs can contain deployment metadata;
review and redact them before sharing.

| Check | Evidence to inspect |
|---|---|
| Fleet state | Full topology-specific `dsse-install -verify` output, including each control plane and Edge |
| Configuration delivery | Each Edge has applied the control plane's configuration; compare epoch and generation together |
| Customer operation | Recent device report, allowed and denied test flows, correct customer in the Console |
| Audit delivery | Test decisions appear for the same customer and time window; look for ingestion refusals and spool growth |
| Certificates | Current validity and renewal state of deployment, transport, device, and inspection certificates |
| Storage | Free space and growth of Postgres, ClickHouse, and Edge audit spools. Without S3, hot-event history remains local and disk/backups must accommodate it. With external S3, the operator-only `GET /admin/archive-health` and Console retention view show the latest bucket probe/Put/Get failure class, rows due for archival, outbox delivery backlog, and last successful webhook delivery. Confirm the real outage, replay and webhook path before accepting an S3 deployment |
| Connectors | Run the connector verifier on its host; check every configured regional endpoint |
| Endpoint software | Actual running version, local verifier results, and rollout status |

An S3 deployment plan requires `archive.webhook_url`, an HTTPS receiver without
credentials or a query string. The installer generates the CP's PostgreSQL
domain-event outbox flag and a deployment-scoped webhook publisher service.
`DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET` is generated in private `deployment.env`;
configure the receiver with the same secret and verify one signed delivery.
The public plan contains only the receiver URL. Never copy the secret to an
Edge-only host or the public repository.
The health event stream is `cold_archive_health_events`. Its payload contains a
failure class and backlog counts, never a bucket name, endpoint or credential.
The `-retention-poll` setting controls the S3 probe as well as retention; its
default is one hour. An outage that starts just after a probe may therefore
take almost one hour to appear in the health state or webhook. Operators can
shorten that interval for faster detection. `-cold-archive-alert-after`
defaults to two hours for an overdue-backlog alert; this is separate from the
first S3 failure notification.
Outage/recovery transitions are durable in shared CP state until the outbox
accepts them. The Console shows pending/dead outbox deliveries and the last
successful webhook; no successful delivery means the path is unverified.
The real S3 fail/recover path still requires release acceptance.

Manual hot-log deletion is available on a CP with shared PostgreSQL job state
and a PostgreSQL hot store in that same database, or a ClickHouse hot store
with an insertion timestamp. It does not support a JSONL-only hot
store. `POST /admin/manual-hot-log-delete/preview` requires
`admin.retention.write` and an explicit `tenant_id`, `stream`, and UTC `before`
timestamp. A customer administrator can name only their effective tenant;
an operator must first select the target organization. PostgreSQL preview
freezes physical row receipts; ClickHouse preview freezes an insertion-time
predicate. Both select by event time (`occurred_at` in PostgreSQL, `ts` in
ClickHouse) and return a count and confirmation digest. If any
previewed row disappears before first confirmation, the job becomes stale and
requires a new preview. The
Console shows that deleting unarchived hot rows loses them permanently while
existing S3 objects, including Object Lock, remain unchanged. Confirm with
`POST /admin/manual-hot-log-delete/{job_id}/confirm` and the returned digest;
then poll `GET /admin/manual-hot-log-delete/{job_id}`. A queued response is not
completion. `GET /admin/manual-hot-log-delete` lists recent jobs for the
current tenant; an operator can use `/admin/manual-hot-log-delete/all` for
deployment history. The shared job ledger records requester, scope, cutoff, count,
progress and failure without storing it among the erasable hot rows. A legal
hold blocks preview and the start of each destructive operation. Confirmation
is refused if its audit request cannot be written. After a CP interruption the
new leader resumes PostgreSQL receipts or identifies the already-submitted
ClickHouse mutation; retry a failed job only after fixing its reported
condition. A definite ClickHouse rejection is marked failed and can be
reconfirmed after repair. Each ALTER carries the durable job ID as its
`query_id`. After an ambiguous response, the worker checks that query in
`system.processes` before consulting `system.mutations` on the same single-node
MergeTree authority. A query can still be waiting before mutation registration;
an unavailable observation is not evidence that it stopped. If no mutation has
ever been observed, absence from both tables (or a currently empty target)
leaves the job running for investigation. It is never automatically resubmitted.
A previously observed mutation that disappears with remaining rows becomes
failed after its issuing query is no longer running; an active mutation remains
running. This procedure does not establish distributed ClickHouse acceptance.
An operator can request cancellation of a stalled running ClickHouse job with
`POST /admin/manual-hot-log-delete/{job_id}/cancel`, supplying
`{"confirm":true,"reason":"..."}`. The request is audited before `KILL MUTATION`
is sent. Cancellation does not roll back rows already removed; keep the legal
hold fence until the worker reconciles ClickHouse and the job becomes terminal.
If the mutation has not been observed, cancellation reports that acceptance is
unconfirmed instead of claiming success: `KILL MUTATION` cannot cancel an ALTER
that has not registered a mutation. The unresolved job and its hold fence remain.
See [ClickHouse's KILL MUTATION reference](https://clickhouse.com/docs/reference/statements/kill#kill-mutation)
for the cancellation and partial-change semantics.
Other tenants' queued jobs continue while one mutation is stalled. A newly
requested legal hold is rejected while a ClickHouse mutation
is unresolved: deletion already submitted to ClickHouse cannot be promised away.
Wait for the job to reach a terminal state, then place the hold and verify the
remaining rows. An uncertain submission remains active for investigation and is
never automatically submitted again. ClickHouse previews count rows rather than copying receipts. One
asynchronous predicate mutation deletes rows inserted before the preview time,
and `completed` means a follow-up count for that same tenant, stream, cutoff,
and insertion-time predicate is zero. Later arrivals with older event times
remain outside the job. Physical disk reclamation can lag. The
`confirmed_absent_count` is the original preview count confirmed absent,
including rows removed by concurrent normal retention; it is not a count
attributable solely to the manual mutation.

Choose check frequency from the lab's risk and workload. During an endurance run, record
start/end times, interruptions, workload, and certificate renewal events. Do not silently
restart the system and count the interval as uninterrupted operation.

The full fleet verifier includes active probes and can exercise enrolment using its
administrative credential. Treat it as a planned verification action and record it in
the test timeline; it is not a passive monitoring command.

## Upgrading persisted user risk

Before upgrading a deployment that uses manual user risk, read
[User risk state upgrades](user-risk-state-upgrade.md). User marks now include a tenant
and a distinct entity type. The state format and the fast risk feed both change;
all control planes and enforcing Edges must use the compatible revision.

## Change a policy or organization setting

1. Confirm the Console's organization context and the administrator's delegation.
2. Record the current setting and the intended allowed/denied result using synthetic data.
3. Save on the control plane. Allow its configuration synchronization cycle to reach the Edges.
4. Check the intended path through each relevant region and confirm the decision in audit records.
5. If the result differs, use [Troubleshooting](troubleshooting.md) before widening access.

A successful save proves persistence at the control plane; it does not prove fleet-wide
enforcement. Generation numbers from different epochs are not directly comparable.
Narrow the initial broad Internet Access rule and explicitly review Connector OBSERVE
mode. Configure and attach a DLP policy if upload inspection is required.

## Restarts and upgrades

For a single-machine lab, the generated Compose project can be stopped without deleting volumes:

```sh
cd "$DSSE_DIR"
docker compose -p dsse --env-file deployment.env stop
docker compose -p dsse --env-file deployment.env up -d
```

This interrupts that machine's services. On a three-region deployment, maintain quorum:
operate on one region at a time and restore its health before proceeding. Follow the
actual project name on each host. `down -v` deletes volumes and is not a restart procedure.

Before a service upgrade, retain the old revision and images, preserve recoverable state,
and review changes to configuration and storage. This release permits incompatible changes
without a migration path; replacing an image with an older one is not guaranteed to undo
a state migration. Validate the target revision on a separate lab before changing a fleet.
After a change, repeat fleet and endpoint checks plus allowed/denied traffic tests.
Use [Agent updates](agent-updates.md) for endpoint packages and signed manifests.

## Backups and recovery preparation

Inventory the founding authority material, generated configuration, shared stores, object
storage, and Edge audit spools. Protect private keys and backups with access controls and
encryption. A carry archive excludes `authority/` and is not a complete backup.

Coordinate a consistent backup using the storage components' supported mechanisms.
Copying live database files is not, by itself, evidence of a restorable backup. Record
the matching software revision and trust material. Validate restoration in an isolated
environment, preventing restored identities and services from reaching the active fleet.
Confirm administrator access, configuration, device identity, audit history, and actual
traffic after restoration. Record the measured recovery time and any data loss.

For the optional local-only audit-store acceptance, run
`scripts/verify_local_audit_restore.sh REPORT_DIR` from a checkout with Docker.
It starts isolated containers using the installer's pinned ClickHouse image and
schema, makes a **cold** copy after stopping the source, and checks the restored
events, rollups and new writes. It creates no S3 dependency and does not touch
running deployment volumes. Keep its private report and checksum; the included
archive contains synthetic data only. This is a component smoke test, not a
complete fleet restore or permission to copy a live ClickHouse volume.

For lost administrator credentials, see the owner-level
[break-glass procedure](deployment.md#break-glass-and-closing-it). Do not re-mint the
deployment as account recovery. A new authority is a different trust relationship.

## Retiring a device or deployment

Block or remove the enrolled device in the Console and uninstall it using the platform
guide. Verify restored connectivity and review residual identity and CA material by
fingerprint. Package removal does not revoke server-side identity, and deleting one
current CA file does not remove previously trusted certificates.

Before retiring the whole lab, account for every endpoint and connector, required audit
retention, backups, and trust material. Remove storage only after those dependencies have
been handled. See [Verification](verification.md) for a record of what was actually checked.

See [Audit logs and data handling](audit-and-data.md) for store-specific retention and
[Administration](administration.md) for roles, delegation, and recovery authority.

### Incomplete usage records

`GET /admin/usage/summary` returns 503 when the durable usage data cannot be
read completely. A database outage, an unreadable spool, or known record loss
must not be interpreted as zero usage. `GET /admin/usage/health` reports storage
unavailability, pending records, spool errors, and tenant-scoped `dropped_records`.
The dropped count covers this process lifetime; restarting does not recover lost
records. Preserve logs and reconcile the affected period before relying on its
usage totals.

If the usage spool is malformed, the process preserves it and refuses further
appends to that file. New unsaved records enter the existing bounded memory
fallback, and health remains degraded. Restore database access promptly and
repair the preserved spool separately. The memory fallback is not durable and
can lose records on process exit or overflow.

### Durable DNS and DLP policy

An existing unreadable or invalid `-dns-policy-store` prevents startup. The
process preserves the operator's file instead of replacing it with boot
configuration. Restore a valid policy before restarting.

`-dlp-rule-store` uses the same persistence model as the other DLP libraries:
`-state-dir` supplies a local path, the control-plane database supplies the shared
`dlp_rules` record, and receiving Edges keep a local cache of the signed bundle.
Without a configured state directory or durable store, standalone DLP rules are
volatile. An acknowledged rule change is saved before it is published. In the
signed DLP bundle, a missing `rules` field preserves rules from an older sender;
an explicit empty object removes them.

DLP device-risk detections are isolated by tenant and device. Each detection is
retained for the longest risk window in the policy that produced it; configured
windows longer than one day are honored. A later policy with a shorter window
does not erase that retained history. Increasing a window cannot recover records
that have already expired, and this in-memory history resets on restart.

### Temporary storage for streaming DLP

Streaming email detection and exact-value allowlisting do not impose a maximum
body length. If a blocking scan cannot yet decide a long match, it holds those
bytes in an encrypted temporary file instead of retaining the whole match in
memory. The process needs a writable OS temporary directory (`TMPDIR` on Unix).
Each spill uses a private directory and file; its encryption key is not saved to
disk. Consumed encrypted frames are reclaimed as the stream advances.

Creation, write, or authentication failures stop forwarding the pending bytes.
Normal completion, rejection, and request-body closure remove the spill. A
forced process termination can leave encrypted temporary files behind; normal
cleanup is not a guarantee against that case. Operators should account for
temporary disk availability and inspect orphaned files after an abnormal exit.
No plaintext body or matched value is added to DLP findings or logs.
