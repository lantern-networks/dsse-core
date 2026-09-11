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
startup setting; it does not erase records immediately.

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
