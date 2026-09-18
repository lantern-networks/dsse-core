# Administrator access and customer delegation

This guide covers Console administration, not end-user [IdP sign-in](idp.md) or
[East-West OOB grants](east-west-policy.md). The role catalog and sensitive-operation
list describe the current experimental implementation and may change.

## Identity, role, and organization are separate checks

An administrator has a home organization and assigned roles. The selected Console
organization determines the requested context; selecting a customer does not itself
grant access. In a deployment using the tenant model, cross-organization administration
requires both membership in the configured operator organization and the relevant
cross-organization permission. Customer delegation is an additional requirement.

**`super_admin` is a role, not proof that its holder is the deployment operator.**
A customer's `super_admin` administers that customer; the role name does not authorize
reading another customer's policy, keys, or logs. Deployment-wide routes have additional
operator-boundary checks. With the tenant model enabled but no operator organization
configured, cross-organization administration is refused.

| Role | Current permission profile |
|---|---|
| `owner` | Wildcard permission role; protect its credentials as highly privileged. Organization and route boundaries still matter |
| `super_admin` | Top organization administrator; has `admin.tenant.admin`. Cross-organization reach still depends on operator membership and delegation |
| `tenant_admin` | Derived from the within-tenant `admin` permission set, without `admin.tenant.admin` |
| `admin` | Within-tenant operational administration; not the deployment operator merely by its name |
| `analyst` | Reads selected operational/policy views; can create/read/cancel exports |
| `auditor` | Reads audit and related state; can create/read exports |
| `approver` | State and approval/break-glass workflow permissions, including approval writes |

This is a guide to intent, not a substitute for the current permission catalog.
`GET /admin/rbac/catalog` and each route's authorization determine the exact permitted
acts. In particular, analyst is not "read everything", and read-oriented roles can
still export data. Grant the smallest role set that covers the intended work.

## Create and maintain named accounts

1. Follow [Deployment](deployment.md) for initial bootstrap, then sign in with the named
   administrator and MFA as described in [First use](after-verify.md).
2. Enter the organization where the new administrator belongs. In **Administrators**,
   invite the person and select roles appropriate to that organization.
3. Hand over the invitation privately. The Console does not send an email; the link is
   one-time and expires after 24 hours. Treat it as a credential, including copied messages.
4. Complete activation and the required sign-in/MFA setup. Verify both an allowed action
   and an action outside the account's intended scope.
5. Review roles and accounts periodically. Suspend access when needed, and review related
   API tokens and sessions as part of offboarding. Validate the denial with a new request.

Role assignment has its own escalation checks. The scoped operator role is `super_admin`;
the invitation and role-update routes refuse assigning `owner` in the operator tenant.
Do not infer a supported account-provisioning flow merely because a role is in the catalog.

Administrator OIDC configuration and customer end-user IdP connections are separate.
Successfully configuring the customer's IdP does not configure Console sign-in or prove
the administrator's MFA behavior. Verify the actual administration login path you use.

## Durable first-party authentication

Use a durable `-first-party-store` (a file path or `postgres`) when administrator
credentials must survive a restart. `memory` does not provide restart persistence.
Successful TOTP sign-in records the consumed time step alongside the credential, so
restarting with the same durable state does not make that code reusable. One-time
recovery-code consumption is also saved before sign-in succeeds. A credential write
failure refuses sign-in rather than issuing a session whose replay protection was not saved.

For PostgreSQL, the component startup migration includes
`048_admin_local_credentials_totp_counter.sql`,
`049_admin_local_credentials_revision.sql`, and
`051_admin_credentials_writer_protocol.sql`. The default
`-postgres-run-migrations=true` applies it before credential loading. If migrations
are disabled, apply these migrations through your database upgrade procedure before
starting the updated binary. Back up the credential store and validate the upgrade
on a separate environment first.

Older file snapshots and database rows have no consumed-step history; the new field
starts at zero and protection is established by the first successful sign-in after
upgrade. Previously consumed codes cannot be reconstructed. Stop all authentication authorities for this upgrade, apply the migrations, and
restart them with the updated binary. Do not run mixed versions: older binaries do
not participate in the concurrency checks. After migration 051, the database rejects
credential INSERT, UPDATE, DELETE and TRUNCATE statements that do not declare the
supported transaction-local writer protocol. This makes writes from older binaries
fail explicitly instead of silently overwriting newer state. It also affects manual
maintenance scripts; review and update them before this migration. Do not disable
the trigger or set a session-wide protocol value to keep old writers running.

The writer protocol is a compatibility guard, not an authorization boundary against
a database owner or arbitrary SQL access. Reads from an old process are not blocked,
and a process retaining old in-memory credentials may still serve stale state.
Stop all authorities during upgrade even though legacy database writes are refused.
The guard requires migration 051 and applies only to PostgreSQL, not shared files.

PostgreSQL credential writes compare a database generation before accepting a
change. Simultaneous consumption of the same TOTP or recovery code through separate
authorities sharing this database permits only one successful save. A stale write
is refused, the local credential snapshot is refreshed for the next request, and
the failed operation is not automatically retried. A sign-in conflict returns a
storage-unavailable response; restart the sign-in flow with a fresh code.

This does not provide continuous synchronization of existing session authorization
across authorities. Independent databases and shared JSON files are not coordinated
by this mechanism. PostgreSQL deletion is tenant-scoped and generation-checked as well: a stale
individual or tenant-cascade deletion cannot erase an account recreated at the same
email address. Conflicts fail the request and refresh local state without retrying
the deletion automatically. A tenant cascade stops at its first failure and can
have already removed earlier accounts; inspect the reported outcome before retrying.

Full tenant erasure also sweeps residual database rows on the local node. Its
credential-table batches use the same transaction-local writer protocol and count
only committed deletions, including a successful zero-row cleanup. If the preceding
account-deletion phase fails, the residual credential sweep is skipped rather than
bypassing its refusal. Failures keep the tenant deletion/erasure records for retry.
This operation is not one atomic transaction across all tenant stores.

Tenant deletion retires inventory identities as disabled removal records. They
retain the tenant association needed to find device-keyed records during erasure
and retries. These removals are carried in inventory distribution; they are not
active devices. The local footprint counts disabled and removal records as retained
data, rather than counting admitted devices only.

During a purge, an origin admission block is removed only after its snapshot saves
successfully, and the change advances the revocation generation. A failed save
retains the live block and inventory ownership records for retry. Received-region
and pulled blocks are separate authorities and are not removed by this operation.
Tenant risk erasure saves the selected device marks and the tenant's user marks
in one shared snapshot before publishing either removal. A failed or unconfirmed
save keeps both live sets and their generation unchanged; the purge reports a
failure and retains inventory ownership for retry. Completed synced in-place saves
are accepted. An explicit retry saves again even if no matching live marks remain,
so a prior ambiguous write can be reconciled. This does not make all tenant stores
one transaction or confirm propagation to other nodes.

Inventory ownership is erased after the preceding cleanup reports no failures.
An incomplete purge returns `complete: false` with failures and remaining counts;
the administrative audit records `partial`. Deletion and purge audits belong to
the acting operator's organization, with the removed tenant as their target.

The Tenants page keeps **Retry erasure** after an unconfirmed purge, including a
connection failure. It retries the purge without deleting the organization again.
Success requires a matching tenant and footprint, `complete: true`, zero remaining
records and no failures. This confirms the reported local scope only: review
`not_counted` storage and other nodes separately. Pending notices survive page
navigation within the open Console, but are not a durable work queue. If the
browser session is lost, use the authenticated `POST /admin/tenants/{tenant_id}/purge`
endpoint with the matching `confirm_tenant_id` after inspecting its footprint.
Do not recreate an organization merely to retry its erasure.

If inventory retirement cannot confirm saving, it retains a restrictive live
removal but stops the purge before other stores are erased. A storage error may
leave either old or new bytes. Reconcile and retry before restarting; restoring
storage or restarting alone is not confirmation. Completed synced in-place writes
remain accepted with a warning, while an unconfirmed flush is rejected even when
it also carries that warning. Existing removal-record retention limits still
apply, so resolve pending erasures promptly. For tenants deleted by an older
version, ownership may already be missing: recover that mapping from trustworthy
records before concluding that unassigned device-keyed data has been erased.

Credential persistence calls carry a five-second deadline. PostgreSQL honors that
deadline; filesystem operations are not guaranteed to be interruptible. Existing
session checks and principal labels read the last committed account snapshot without
waiting for a credential write. Suspension and role changes take effect after a
successful save; a failed save does not publish the requested change.

An authenticator replacement starts a new step history. Account activation still
allows immediate sign-in with the current code; the first successful sign-in consumes
it for subsequent authentication attempts.

Activation attempts with a valid invitation are audited under the target account's
organization. Invalid or expired invitations cannot establish an organization; review
those failures in the node organization's audit trail, rather than expecting them in
a customer's account history. Audit records do not contain invitation tokens,
passwords, authenticator secrets, or recovery codes.

## Delegated operation inside a customer

When creating an organization, **Who runs it → We run it for them** establishes the
standing delegation described in [Organizations](organizations.md). Without it, an
operator entering the customer is refused even for reads, including device configuration
and logs. Confirm the customer name in the header before each administrative change.

Some sensitive acts require a further **20-minute elevation** inside the organization.
Examples include creating customer authorities and selected authority rotation or removal
operations. The Console explains the act and records that the operator took this access
and when it ended. The window does not renew automatically. It governs the delegated
operator path; it is not an end-user authentication grant or a blanket rule that every
customer administrator must elevate for every change.

Customers can withdraw their operator delegation. The operator must not be able to
reopen a delegation the customer withdrew through the ordinary delegation control.
After withdrawal, test operator reads and writes with the previous session and confirm
the customer can still administer its own organization. Review the audit record for
delegation, elevation, the actual change, and withdrawal as distinct events.

## Recovery is a separate authority

Generated deployments initially arm an owner credential while the
`runtime/admin-bootstrapped` marker is absent. Bootstrap and service recreation close
that initial path. Lost-account recovery requires access to the founding control plane's
deployment directory; use the canonical [break-glass procedure](deployment.md#break-glass-and-closing-it).

Protect filesystem and service-control access accordingly. Customer delegation does not
remove the host operator's ability to change the running service or restore its state.
Treat recovery as a privileged, recorded operation: retain the reason and actor, confirm
named-account access, close the recovery path, and verify the deployment afterwards.
Do not re-mint deployment CAs to recover an administrator password.

## Boundary checks before handover

| Actor / condition | Check |
|---|---|
| Customer administrator | Own customer works; another customer's identifiers/context are refused |
| Operator without delegation | Customer read and write are refused |
| Delegated operator without elevation | Routine authorized work works; an elevated act is refused |
| Elevated operator | Intended act works; expiry ends that authority |
| Customer withdraws delegation | Previous operator context no longer authorizes customer access |
| Analyst / auditor / approver | Test exact required routes, including export and write boundaries |
| Suspended account / revoked token | A fresh request using the old credential is refused |
| Recovery completed | Named login works and the initial owner path is closed |

Run these checks in disposable organizations with non-sensitive data; record failures
as limitations, not as a reason to broaden roles until the test passes. This table is a
verification plan, not a report of a completed live isolation audit.

Implementation: [role permissions](../cmd/dsse-edge/admin_auth_store.go),
[operator organization gate](../cmd/dsse-edge/operator_is_an_organization_not_a_role.go),
[elevated acts](../cmd/dsse-edge/operator_elevated_acts.go).
Continue with [Audit logs and data handling](audit-and-data.md).

## Device block and allow failures

The Devices page changes transport admission first, then the enrolled inventory.
These are separate operations. If the transport request fails, the Console retains
an error and does not send the inventory change. Use **Retry** after resolving the
error; a partial operation is not a successful device update.

The list, blocked count, status filters and row action combine enrollment status
with the tenant-scoped transport block list. A failed or invalid block-list read
shows an error with **Retry**, rather than treating unknown state as unblocked.
These are the responding control plane's latest observations, not acknowledgements
from every region or proof of an active endpoint connection.

A successful restore removes only the locally authored transport block. The response
includes `transport_revoked`, indicating whether a pulled or received-region block
still applies on that server. If it is `true`, the domain audit is `partial`, the
Console leaves inventory admission unchanged and displays the remaining-block
warning. Resolve the originating block and verify its withdrawal, then reload or
retry. The common HTTP audit can be `success` because the local restore itself was
acknowledged. `restored: true` alone does not mean all admission gates are open.
An older server without this outcome field cannot confirm an Allow action for the
updated Console; upgrade the server and Console together.

The Console binds block/allow writes to the organization of the loaded list. An
`expected_tenant_id` mismatch returns HTTP 409 before changing state. This optional
precondition does not grant access; normal authentication and authorization remain
required. These separate requests do not provide a transaction or protect against
all concurrent changes after an acknowledgement.

Admission-state reads do not wait for the revocation store's save or reload I/O.
During a pending block, the list can already show that identity as blocked before
the administrative request returns. During a pending Allow, the previous local
block remains visible until saving succeeds. A pending operation has not yet
confirmed persistence or produced its completion audit.

Persisted updates and store replacement still run one at a time. Slow storage can
therefore delay administrative writes, subsequent queued writes and the callbacks
or registered-session closure that follow them. This separation keeps admission
reads available; it does not impose an I/O deadline or promise instant disconnection
of existing sessions. A reload keeps the previous live state readable until the
entire replacement has been read and validated.

With admission persistence configured:

- **Block:** the local transport block takes effect and registered sessions for that
  device are closed even if saving fails. The API returns HTTP 503, and the domain
  audit records `partial`, `applied_locally: true`, and
  `persistence_confirmed: false`. This does not confirm enforcement on every node.
- **Allow:** the local transport block is lifted only after saving succeeds. A save
  failure returns HTTP 503, keeps the live block, and records an `error` domain audit
  with `applied_locally: false` and `persistence_confirmed: false`.
- The common request audit records `error` for either 503. Repair storage and retry
  the intended operation explicitly. Retrying an already active local block saves
  it again, without changing its generation or repeating propagation callbacks.

A storage error can occur after new bytes were written. The live state and saved
snapshot can therefore differ: failure does **not** guarantee disk rollback, and a
restart alone does not prove recovery. Reconcile the saved revocations with the
intended state and complete the retry before restarting. Preserve other devices'
blocks when reconciling; do not delete a snapshot to bypass an error. A subsequent
successful save also includes existing local blocks whose earlier save failed.

A completed, synced in-place write is still accepted, with a server log warning
that replacement was not atomic. An unconfirmed flush is rejected, including
when it also carries that compatibility warning. With no persister configured,
admission remains in-memory only and does not survive a restart. Restoring a local
block does not clear a block received through the control-plane feed or region mesh.

### Receiving a block from another region

With admission persistence configured, a mesh delivery that cannot confirm saving
returns HTTP 503 while retaining the live block. The sender keeps that delivery
pending and retries. An unchanged delivery also retries saving; it does not increase
the revocation generation or repeat propagation callbacks. A successful response's
`applied: false` means the block was already present, not that it was ignored.

Shared-secret deliveries require a fresh signed request on each retry. Reusing the
same signed request is rejected by replay protection, even if its save failed.
The built-in sender generates fresh signatures for retries. Update receiving
control planes to obtain these save acknowledgements; older receivers can return
success without confirming storage. No configured persister still means volatile
state, and no acknowledgement proves enforcement on every edge or closes an
existing session by itself.

Receiver system logs distinguish `persistence unconfirmed` from `accepted` and
record the authenticated peer separately from the payload's `claimed_origin`.
These machine deliveries are not administrator actions in Logs & Audit. Console
block/allow actions retain their administrative audits. A local Allow cannot
withdraw the received-region block; it reports the remaining block and leaves
inventory admission unchanged. Fix storage and allow delivery to complete before
restarting; deleting the snapshot is not a recovery procedure.

### Revocation and risk state when the control plane changes

With shared Postgres stores, a control plane reloads saved admission and typed
device/user risk state before advertising leadership. An unreadable or invalid snapshot keeps it
on standby; restore readable, valid storage and let election retry. A missing
snapshot after this process has observed or changed state also refuses promotion.
An empty first boot remains supported. Shared-store migration remains an explicit
operator action when an existing node-local snapshot takes precedence.

A standby returns HTTP 409 for the revocation feed, the Console's connection
block status, and both device and user risk snapshots (`GET /admin/risk-signals`).
Risk is refreshed during promotion; a healthy snapshot held by a standby can
still predate another administrator's change and is not an authoritative read.
Devices and People show an error with Retry and withhold risk-change controls.
Use the active management server through the deployment's front door, or retry
after promotion succeeds. A leader with unreadable risk storage instead returns
HTTP 503. Standby refusals do not change the held risk, storage health or saved
settings, and reads do not create administrator-change audit events.

Edges retain their last applied set when the revocation feed is unavailable.
Check Edge synchronization separately after recovery: a local administrator
response is not a fleet receipt. These read checks do not change the traffic
engine's handling of retained state or add periodic risk refreshes on standbys.
Single control planes without election and enforcing Edges retain their existing
read behavior. The check uses locally known leadership; it does not fence a
response already in flight or eliminate the election loop's detection interval.

New control planes use the shared database for risk when a database is configured
and no local risk snapshot exists. Existing local entries, including empty files
and directories, stay selected for inspection and recovery. An inaccessible local
path does not silently select the shared database instead. The existing
`high_risk_devices.json` filename
and shared `high_risk_overlay` row remain compatible. A local snapshot still takes
precedence; migrate it explicitly with `-high-risk-store=postgres+import:<path>`
after backing it up and coordinating a single writer. Confirm shared state before
resuming the other control planes. For admission, the corresponding flag is
`-admission-revocation-store=postgres+import:<path>`.

Nonempty legacy risk snapshots need device/user attribution using the enrollment
ledger and identity directory. Startup retains that migration path; promotion
refuses a newly encountered unattributed legacy snapshot. Resolve the attribution
through controlled startup or recovery before retrying. Do not clear the snapshot
to make a standby appear ready.

Reloading persisted state is not a new administrator action. Existing block and
restore audit records remain the records of those changes; the system log reports
failed preparation or acquired leadership.

### Limits of restoring a block in the optional admission mesh

This limitation applies when `-revocation-mesh-peers` is explicitly configured.
The generated deployment does not enable this mesh: its control planes use a
shared database, and Edges pull revocations from the active control plane. That
pull path can remove a synced block when it receives the authority's complete
updated set. Mesh-received blocks are a separate layer. Existing node-local
state can also override the shared-store default and needs deliberate migration.

Allow changes the locally authored block and inventory admission on the management
server handling the request. It does not send a withdrawal to the other regions.
After A blocks a device and B receives it, allowing the device at A can leave it
blocked at B. The received block survives a restart. Allow at B still reports a
remaining block and a partial domain audit; the Console does not send an inventory
enable request in that case. Repeated Allow requests do not withdraw that entry.

The current admission mesh carries revocations only. It does not implement
versioned withdrawals or retain separate ownership for each origin's received
block. Re-enrollment does not supply that missing withdrawal protocol. Do not
interpret successful local admission or an empty sender queue as a fleet-wide
restore. A received block requires deliberate state reconciliation; deleting the
whole admission snapshot or enabling inventory alone is not a safe substitute.
Preserve unrelated local and received blocks during any operator recovery.

The Block confirmation explains this limitation, and the Allow success message
names local admission. Devices shows a connection error with Retry when the
management server cannot be reached. Retry reloads current state; it does not
establish that every region is reachable or has completed an update.

### Sending a block to another region

The sender keeps a pending entry for each peer region and device. Its system logs
report the result of saving that queue: `saved`, `saved_non_atomic` (a completed,
synced in-place write), `volatile` (no storage), or `unconfirmed`. Failed saves,
including unconfirmed flushes, leave the entry in memory and are retried during
the existing delivery loop. A later confirmed queue save includes all pending
entries. Storage failures are reported without exposing backend paths or errors.

Peer acceptance and removing the pending entry are separate outcomes. After a
peer returns HTTP 200, `peer_accepted=true` reports that acknowledgement;
`removed=false persistence=unconfirmed` means queue cleanup still needs saving.
The running sender retries cleanup without resending the accepted request. It
removes the live entry only after confirming the save. An acknowledgement for an
older enqueue cannot remove a newer entry for the same region and device, even
when their payloads are identical.

A configured outbox only supports restart recovery for state that reached storage.
On startup, saved pending entries are retried, so an already accepted delivery may
be repeated after a restart. The receiver must tolerate that duplicate and still
confirm its own save. Delivery uses the existing retry window of approximately
ten minutes, with backoff up to thirty seconds; this is not a storage I/O timeout
or a continuously scheduled retry service. After the window ends, a pending entry
can remain until the process reloads the saved queue. Fix storage and inspect the
queue outcome before restarting: a failed enqueue may have no recoverable copy.
Do not delete the outbox to clear an error.

Console Block status and successful administrator audits describe the local
admission and inventory changes. They do not acknowledge queue durability or
acceptance by every peer. Use sender system logs to distinguish those outcomes;
automatic deliveries and cleanup retries do not create administrator audits.
Snapshots remain readable while an outbox save is pending; other queue writers
wait for that save. This is process-local coordination, not a transaction with
local admission or a lock shared by several server processes. Region-block withdrawal remains separate from queue persistence.

### Restoring the region delivery queue

When mesh peers are configured, startup loads the complete saved outbox before
resuming delivery. An existing empty file, `null`, malformed or trailing JSON,
null or incomplete entries, unknown or duplicate fields, and duplicate
region/device entries are rejected. No valid subset is adopted and the rejected
snapshot is not rewritten. Load errors are reported without stored values or
backend paths. Missing storage on first boot and an explicit empty array `[]`
remain valid; deleting a lost queue is not equivalent to recovering it.

Each entry requires `region`, `url` and `identity` strings. Region keys use the
configured lowercase, trimmed form without control characters. Device identities
use the existing admission normalization (lowercase and trimmed); this does not
introduce a new identity character policy. Legacy entries may omit `reason`,
`origin_region` and `enqueued_at`, or retain their existing string values. These
metadata fields are not interpreted as a new schema or strict timestamp format.
A present null or non-string field is rejected.

Peer configuration and restored URLs require an absolute HTTP or HTTPS base URL
with a host. Userinfo, queries, fragments and malformed URLs are refused before
delivery. A path prefix is supported. HTTP remains available for existing lab
configurations; these checks do not establish TLS trust, peer ownership, or bind
a restored URL to today's configured peer list.

To recover, stop the affected process and restore a complete, trusted backup of
the pending queue. Preserve the rejected file for diagnosis. Check the configured
peers and storage access, then restart and inspect resumed delivery and cleanup
outcomes. A previously open Console cannot identify a startup failure's cause;
it shows a read error until the server is available, then Retry reloads the state.
If mesh peers are disabled, the unused outbox is not loaded or sent. Inspect it
before enabling mesh again. Local blocks, queue storage and peer enforcement
still have separate outcomes; a valid snapshot alone does not prove fleet delivery.

### Restoring admission state at startup

When an admission snapshot exists, the server validates the complete local and
received-region revocation maps before using them. A read error, empty file,
malformed JSON, unsupported schema, duplicate or unexpected field, null map/reason,
or noncanonical identity stops startup. Identities must match the lowercase,
trimmed form written by the server; reasons must be strings in their stored,
trimmed form. Empty reason strings remain valid. Older `v1` snapshots without
`mesh_received` are supported and restore an empty received-region layer.

A failed restore does not replace an existing in-memory state or its storage
writer. Restore errors use fixed messages without saved identities or reasons.
A valid replacement replaces both persisted layers together; the runtime feed
layer is separate. Loading a snapshot does not trigger an administrator kill switch
or send new revocation reports.

Check the configured path/database, access permissions and retained backup when
startup reports an admission restore error. Recover a valid complete snapshot with
the intended blocks before starting the server again. Do not clear a file, remove
rows, or change to a new empty path merely to make startup succeed. A missing
snapshot still means first boot under the storage contract; it is not evidence
that previously stored blocks were intentionally removed. Backups and correct
storage attachment remain necessary to detect and recover a missing snapshot.


## Device risk changes and saving

Use **Devices → More → Risk** to set or clear a device's risk. An administrative
request first validates the input and confirms saving the shared risk overlay,
then updates the device runtime metadata. An unconfirmed overlay save returns 503;
that request does not publish the overlay change or attempt the runtime update.
The Console retains a warning with **Retry**, and `device_risk_change_failed` records
the target device, requested severity, actor and `applied: false`. The common
administrative request audit also records the error. Invalid or unauthorized
requests remain separate refusals and do not produce an applied-risk audit.

When the overlay save succeeds but runtime saving fails, the response is partial:
the live runtime metadata was updated, while its saved copy may still contain the
old risk. The Console warns and offers **Retry**; `device_risk_changed` records
`partial`. Response and audit fields distinguish `runtime_persistence_warning`
from `overlay_persistence_warning`. A volatile overlay or a completed non-atomic
save is accepted with an overlay warning. An unconfirmed flush is an error, even
if the storage implementation also reports a non-atomic-save warning.

Reapply the intended risk after restoring storage and inspect the displayed state.
An explicit retry saves an unchanged overlay too, without advancing its generation
again. A save error can leave old or new bytes; it does not prove disk rollback.
Reconcile before restarting. If runtime saving failed, a restart can restore old
runtime risk even when the overlay was cleared. The Devices risk badge includes
runtime information, so inspect it and retry the intended change; restarting alone
is not recovery. Browser navigation or a new session is not a durable retry queue.

These two stores are not one transaction. A successful local response does not
confirm independent-region delivery or coordinate concurrent administrators across
processes. Automatic DLP signals use a separate checked escalation path: stronger marks
become live before saving and are retained if saving fails. Automatic detections
do not lower or clear an existing mark. Their application and persistence outcomes
are recorded separately from administrative changes (see below). Risk affects access through configured policy;
setting risk does not itself revoke standing grants.

## Restoring saved risk state

The high-risk store contains device marks and tenant-scoped user marks in one
snapshot. Startup refuses unreadable, empty or malformed existing snapshots,
including duplicate fields or identities, missing/null device maps, invalid user
records, field aliases and unsupported versions. A valid `v2` snapshot may omit
`users` when there are no user marks. Device identifiers remain case-sensitive.
Legacy `v1` marks still require attribution against the enrolled inventory and
identity directory before serving; ambiguous marks are not silently cleared.

Keep the rejected file or database record for diagnosis. Restore a complete,
known-good snapshot and verify its ownership and storage attachment before
restarting. Do not delete the snapshot or replace it with an empty map to make
startup succeed. A missing snapshot still means first boot under the storage
contract; the application cannot distinguish that from a previously saved file
being lost. Backups and checks of the configured storage remain necessary.

An explicit failed restoration in a running process retains the previous live
marks and writer but marks the store unavailable. Administrative risk reads return
503 and risk changes are refused until a complete valid snapshot is restored.
This is not continuous monitoring of files changed outside the process.
**Devices** shows a read error and **Retry** instead of a normal risk badge or a
selected clear action. After storage recovery, retry the read and check the
restored marks before making changes. The Console requires the API's device type,
tenant and complete risk map; update the Console and server together.

## Risk reads while storage is slow

A pending risk save or explicit restoration does not hold up reading the published
risk state. Devices, user-risk reads and risk lookup for decisions continue using
the currently published values. An administrative risk change is not applied or
acknowledged until saving finishes. On failure, the previous values remain and
the existing error/retry behavior applies. A pending legacy attribution keeps its
unavailable status until the migration succeeds.

Automatic DLP escalation retains its existing immediate-publication behavior:
readers can see the stronger mark while saving is pending, and that mark remains
live if saving fails. That is not confirmation that the mark survived storage.
The automatic outcome record distinguishes application from persistence, and a
subsequent matching detection retries an unconfirmed save.

Writes to the shared risk store are still serialized, including pulled device
and user snapshots. A slow save can delay another write; this change does not
introduce a storage timeout or a transaction spanning overlay and device-runtime
stores. A successful read shows local published state, not confirmation of delivery
to every region or completion of another administrator's pending request.

## Automatic DLP risk outcomes

When a named DLP policy's device-risk conditions match, the strongest matching
severity is requested. An existing stronger device mark is retained. Risk affects
subsequent access through the configured risk policies; an `observe` upload stays
an observation and its body is not changed by this reporting path.

**DLP Findings** contains the original `dlp_match` detection once. **Logs & Audit →
Logs → Inspection / DLP** also contains a separate `dlp_device_risk` outcome.
Search by decision or device identity, open **Details**, and use **View raw** to
compare `condition_severity`, `applied`, `applied_severity`, `changed`, `persistence`
and `result`. The applied severity may be stronger than the triggering condition.
These are inspection events, not administrator-change audit records. They contain
non-secret detection metadata, never the matched confidential values.

| Persistence | Meaning of this attempt |
| --- | --- |
| `saved` | The configured store accepted the snapshot. |
| `saved_non_atomic` | The store reported a completed, synced in-place save; the outcome is partial to retain the warning. |
| `volatile` | No persistent store is configured; the live mark is not restart-safe. |
| `unconfirmed` | Saving failed or its durability could not be confirmed; the stronger live mark remains, but the outcome is partial. |
| `not_attempted` | No save was attempted. Check `applied` and `result`: an already sufficient mark can succeed without another save, while an unavailable overlay reports an error without applying the signal. This value does not assert persistence. |

The original detection is recorded before risk saving begins. If saving is slow,
readers can already see the stronger mark while its outcome is pending. After an
unconfirmed save, the next matching detection retries the shared snapshot without
incrementing its generation again. A successful shared risk save also resolves
that pending retry. Once confirmed, unchanged detections avoid repeated storage
writes. This is an in-process retry flag, not a timer, persistent queue or guarantee
that another detection will arrive. Recover storage and explicitly retry the mark
through **Devices** before restarting when persistence is unconfirmed. If the
store itself is unavailable after a failed restoration, restore its complete valid
snapshot first; a detection cannot clear that error.

Inspection recording and forwarding remain best effort. An event in the local
Console does not prove durable delivery to every region. Conversely, a missing
outcome is not proof that no live mark was applied. Verify the local device risk
and storage health separately; independent-region propagation and runtime state
are separate checks.

## Empty device-risk feeds

The revocation feed also carries device and typed user risk. A pulling node keeps
its current device-risk marks when the feed's `high_risk` section is missing,
null or empty and the response does not declare `authoritative: true`. It must not
interpret an undeclared blank response as an instruction to remove risk. A valid
nonempty replacement retains the existing protocol behavior.

An authoritative response declares a complete set. Its empty device set can clear
the pulled marks, including when the existing wire format omits the empty map.
If a complete-set declaration follows an ambiguous response at the same epoch
and generation, it is processed; an older generation in the same epoch cannot use
that declaration to roll back state. Risk-based access continues to follow the
configured policies; synchronization does not independently revoke standing grants.

A configured risk overlay that is unavailable or awaiting legacy attribution
cannot serve a complete feed: the API returns 503. A puller with unavailable local
risk state refuses to replace its cached state, including for older feeds without
typed user risk, and reports a sync failure instead of clearing the error on an
unchanged poll. Restore a complete valid snapshot and restart the affected process
to re-establish synchronization. Startup already refuses failed risk restoration.

The sync log distinguishes `device_risk=applied` from
`device_risk=retained_unconfirmed_empty` and reports the local mark count. A
processed generation alone does not mean an ambiguous empty section cleared the
marks. These machine synchronization logs are separate from administrator-change
audits. Pulled device/user sets still use the existing in-memory replacement
contract; this change does not make them one durable transaction with admission
or device-runtime state. Confirm the node's current risk and sync status as well
as the saved configuration when investigating a restart.


### Enrolled inventory during control-plane promotion

A control plane using shared inventory storage reloads both device entries and
device groups before it becomes leader. The existing admission and risk checks
must also succeed. Background standby refreshes cannot overlap that promotion.
If a required read fails, retry through the active management server; Devices,
Device groups and the configuration bundle remain unavailable on the standby.

Restoration requires a complete inventory snapshot. It rejects malformed records
and a missing snapshot after this process has confirmed stored state. A genuinely
new store retains its static seed. Version 1 and unversioned legacy entries still
receive the conservative previous-enrolment marker. An omitted group registry is
an empty registry, matching the existing file writer. Successful reloads update
the distribution generation for device or group changes without rewriting storage.
A valid reload also clears a failed-read write latch.

Device-group creation, editing and deletion audit records identify the acting
administrator and use the `device_group` target type. They can be correlated with
the HTTP audit by tenant, operation, target and timestamp. A successful local
operation still requires separate confirmation of Edge application.


### Device changes when saving is unconfirmed

Adding a device, assigning or clearing its group, changing its declared kind and
removing it produce device-specific audit records with the acting administrator.
Group records include the applied group, including an empty group for clearing;
kind records include the effective kind, including `endpoint` for the default.

If adding, assigning or changing kind is applied locally but saving cannot be
confirmed, the API returns 500 and its operation audit reports `partial`,
`applied_locally: true` and `persistence_error: true`. That change can already
reach pulling Edges. Reload to inspect the current state and retry after storage
is available. An error does not prove the backend wrote nothing or that a restart
will restore the prior value.

An unconfirmed removal returns 500 and retains the previous local inventory,
including removal history. Its operation audit reports `failed` and
`applied_locally: false`; the backend may still contain an unconfirmed candidate.
An absent or already removed identity returns 404. Check storage and retry the
removal rather than treating a storage failure as a completed removal.

The HTTP audit records the request's status separately from the operation outcome.
Successful primary audit writes are also mirrored to the configured audit outbox;
this does not make inventory saving and audit recording one transaction. Confirm
storage health and Edge state separately from the Console response.


The device-group assignment editor waits for a verified group list before enabling
changes. A failed or malformed response shows Retry; an empty registry does not
silently clear an existing assignment. An assignment absent from the registry is
shown explicitly until you choose another value.

While saving, the editor keeps the submitted selection fixed and prevents a
second request. Success requires a response confirming that device, tenant and
group. A failed or unconfirmed response stays visible in the editor; check the
current state before retrying. Closing a loading editor or leaving the page
prevents its late response from reopening the old editor.


### Steering exclusions and save failures

Open **Steering Exclusions → Authored exclusions** to add an app identifier for
an entire tenant, a device group, or one device. Group and device scopes require
the corresponding identifier. Enter one app identifier per line. Matching rules
are combined; deleting one rule does not remove an exclusion supplied by another
matching rule or by an agent's built-in loop-prevention rules.

The list reads the control plane. Enforcing Edges receive the authored set on
subsequent polls. Check device observations separately: an authored rule and a
successful save do not prove that an endpoint has applied it. If observations
cannot be read, the Applied column shows **not known**.

When storage is configured, an unconfirmed save returns HTTP 500 for creation,
editing, deletion, and version rollback. That request keeps the previous local
policy. This is not a guarantee that the backend is unchanged: it may have saved
the candidate before reporting an error, and a later refresh or restart can read
that candidate. Check the current list before retrying, particularly before
creating another rule. A confirmed in-place save is accepted, while a warning
that durability is unconfirmed is treated as a failure. Policy IDs cannot be
reassigned from another tenant.

The editor verifies the organization before enabling changes and disables input
and dismissal while a save or delete is pending. A success message requires a
matching acknowledgement from the control plane. An unreadable, incomplete or
mismatched response stays visible as an unconfirmed result beside your input.
Retrying **in that same editor** reuses the policy ID, so a lost creation response
does not create another exclusion. Each retry is still an upsert and can create
another audit and version-history entry; this is not exactly-once processing or
protection against another administrator's concurrent edits. If you close the
editor, reload the list before creating a new rule.

A delete acknowledgement includes the policy ID and tenant. If a response is
lost and a retry returns 404, the Console does not assume success: close and
reload to check whether the rule is now absent. Leaving the page or switching
organizations discards late editor results, but cannot undo a request already
processed by the server. Console mutations send `expected_tenant_id`; a context
mismatch returns 409 before changing the policy. Legacy API callers may omit
this optional check. Deploy the updated control plane before these Console
assets, since the editor requires tenant-bearing delete acknowledgements.

In **Logs & Audit**, the `steer_exclusion_updated` event identifies the acting
administrator, policy ID, operation (`steer_exclusion_upsert`,
`steer_exclusion_delete`, or `steer_exclusion_rollback`), and result. Unconfirmed
saves record `failed`, `applied_locally=false`, and `persistence_error=true`.
The common HTTP audit records the request status separately; rejected input or
ownership checks produce that rejection record without a policy-change event.
Successful primary operation audits are mirrored to the configured audit outbox.
Policy persistence, version history, and audit recording remain separate writes;
they are not a single transaction.

An operator authorized to write for another tenant also records that tenant as
the owner of the policy's version history and operation audit. The acting
administrator remains the operator; record ownership does not change the actor.


### Verifying exclusion lists and device observations

The authored list verifies the control plane's response format, tenant and policy
rows before displaying settings. A failed or invalid response shows **Retry**;
it does not mean the tenant has no exclusions. Retry reads the current settings
again. Responses from an older reload or a page you have left cannot replace the
current list.

The Applied column needs a complete, verifiable observation set. It shows
**not known** if that read fails, contains another tenant's data, or only returns
the first page of the device reports. The authored list requests up to 200 reports;
a larger fleet therefore needs the separate **Observed on devices** view for
filtered, paginated inspection. Authored rules remain visible when their device
observations are unavailable. These observations are reported by devices and are
not an independent confirmation of endpoint enforcement.

Update the control plane before its enforcing Edges and Console assets. The
exclusion feed now identifies its format as `admin_steer_exclusions.v1` and names
the authenticated `tenant_id`. New readers reject older responses that omit these
fields, retaining their last valid cache or showing Retry. Additional response
fields are compatible with older readers. A correctly scoped, explicit empty
`steer_exclusions` array is the only wire representation of clearing the set.
Missing/null collections, malformed rows, duplicate policy IDs, foreign tenants,
responses larger than 4 MiB, and interrupted reads are rejected. Rejection preserves
the Edge's last valid set; it never changes a foreign row's tenant to make it fit.
Cache persistence remains a separate concern from accepting a complete feed.


### When exclusion storage cannot be verified

The control plane validates the complete stored exclusion set at startup and
before adopting a refresh. Empty files, missing/null policy arrays, duplicate
fields or policy IDs, and invalid policy records are rejected. Existing snapshots
written by the service keep the same format. Do not replace an unreadable snapshot
with `{}` or `null` to make startup succeed; restore a verified backup instead.
An explicit `{"policies":[]}` represents a deliberate empty file-backed set.

If a running process cannot read or validate its storage, it retains the last
valid local set. The authored-list API returns 503, the Console offers **Retry**,
and pulling Edges keep their previous set. Administrative changes are refused
while a refresh error remains known, so a save cannot silently conceal that error.
After storage is repaired, the next successful refresh clears the error and
normal reads and writes resume. Refresh attempts are normally up to five seconds
apart; Retry does not bypass that interval. Enforcement using the retained local
set is not proof that the latest stored configuration has been read.

A file missing on a new process's first load is still treated as first boot.
Once that persistence instance has loaded or saved a snapshot, disappearance is
an error, including after an explicit empty save. That knowledge is in memory:
if a file is removed while the process is stopped, this mechanism alone cannot
distinguish the next startup from first boot. Backups and deployment storage
checks remain necessary. File persistence does not coordinate multiple writers,
and synchronizing an Edge cache still uses best-effort persistence.


### Published agent releases and signing information

**Agent Releases** verifies the response format and publication scope before
showing the active and pending releases. For an operator outside any selected
tenant, both the catalogue and signing floors use the deployment scope. When
operating inside a tenant, they use that tenant. The rollout plan remains scoped
to the authenticated operating tenant, including on the deployment screen.

An unavailable or incomplete catalogue shows **Retry**, not **Nothing published**.
An explicitly empty, valid catalogue still means that nothing has been published.
If only signing information is unavailable, the verified catalogue and its existing
download controls remain visible; signing availability and minimum versions read
**Unknown**. Retry before opening the publication form. A confirmed absence of a
signing key is different: the form can accept a manifest signed elsewhere.
**Minimum version to sign** is a signing restriction, not a device rollback limit.

When publishing an externally signed release, the manifest supplies the target OS,
architecture and version. The form's filename guesses or manually entered values
do not override it. The Console checks the selected package's size and digest
before publication, then sends that same file to the manifest's target. The
selected files and entered fields are captured when Publish is pressed, so a
change made while hashing does not replace the package being checked. Signature
verification remains on the control plane.

Catalogue and signing-floor GET requests accept an optional `expected_tenant_id`.
A mismatch returns HTTP 409 before reading either set; the parameter checks the
server's verified scope and does not select a tenant or grant permission. A present
empty value pins legacy empty scope. Omitting it preserves existing client behavior.
Update the control plane before or together with the Console: a missing endpoint
or an older signing-floor response without `tenant_id` is shown as unknown.

These screen checks validate the display contract. They do not verify signatures
or installer bytes; cryptographic checks remain with the authority and endpoints.
Leaving the page or changing its operating context discards late read responses.
Reading or retrying these public release metadata does not change configuration or
create a configuration-change audit record.


### Agent rollout settings and incident holds

The Console confirms the rollout plan's format, tenant and complete settings
before enabling its three editors. An unavailable, incomplete or foreign response
shows Retry and disables editing; it is not shown as an unset window or an absent
hold. Retry reloads the settings without changing them. A valid unset plan still
displays the device defaults. Late reads from a departed page or changed tenant
are discarded. The published-release catalogue is a separate scope: an operator
outside a tenant may see the deployment catalogue while the rollout plan remains
scoped to the authenticated tenant.

During a rollout save, the editor locks its fields, group-row buttons and dismissal
controls. Success requires a complete response for the verified tenant and matching
values for the settings sent. If the response is missing, malformed or inconsistent,
the editor keeps the input and displays an unconfirmed-save message. The change may
already be stored: retry with Save, or cancel and reload before editing again.
Retries can add audit records; they are not an exactly-once operation. A concurrent
administrator can change other settings, which are merged by the authority.

The editor is bound to the page and operating context that loaded its settings.
Leaving that context closes it and suppresses late notifications; this does not
undo a server-side write. Rollout GET and PUT accept `expected_tenant_id` and refuse
a mismatch with HTTP 409. A present empty value pins legacy empty-tenant scope;
omitting the parameter preserves existing API behavior. Update the Console and
control plane together to apply both the screen and server checks.

In **Agent Releases**, the selected version, installation window and group rollout
order are separate controls. Changing the selected version or choosing to follow
the offered release preserves an incident hold and its reason. The page displays
that hold beside the version preference. Only an explicit `intent=freeze` request
with `frozen=false` and a reason releases it. A hold/release request that omits the
version and channel preserves the existing selection.

Editing the rollout order preserves each retained row's configured priority and
the schedule's `default_delay_days`. Higher priority wins when a device belongs
to several groups; equal priorities use the slower wave. An unlisted device uses
the explicit default, or the slowest wave if there is no explicit default. The
summary shows nonzero priorities and an explicit default. These existing values
are preserved by the editor; changing them through the API requires a complete
wave schedule. A device with no group can still receive the default delay.

A pending newer manifest does not replace the active installer before its package
arrives. The Download button obtains the active version. Saving a version
preference does not establish that any endpoint installed it. Availability of the
named release, incident holds, installation windows and endpoint checks still
apply, and updates reach Edges and devices on subsequent polls.

Rollout changes record `agent_rollout_plan_attempted` before changing the plan,
then `agent_rollout_plan_applied` on success or an outcome with `failed` on a save
failure. These records identify the administrator, tenant, target, action and
result; the configured outbox mirrors each successfully recorded primary event.
The common HTTP audit records the request separately. An attempt without an
outcome needs reconciliation: saving the plan and recording audit events are
separate operations. An outbox failure is logged and does not undo the primary
record or the plan.

The persisted rollout tenant map is validated before startup adopts it. A `null`
map or plan, a missing/null `frozen` decision, duplicate JSON names, unknown or
case-aliased fields and invalid wave/window values are errors, not permission to
resume updates. Existing zero-byte files also fail startup, including through the
shared-store adapter. Startup reports invalid snapshot data without printing saved
tenant names or incident reasons, and leaves the source unchanged.

The existing tenant-map format remains supported: `{}` is an explicit empty map;
legacy plans may omit metadata but must state `frozen`. Absent/null optional
schedules, nil wave lists and omitted/null default delays keep their existing
meaning. The empty tenant key used by legacy single-deployment installations is
retained in its original scope. A present maintenance window must carry all its
fields. No migration or automatic reset is performed. Recover the complete intended snapshot from a
trusted backup before restarting; deleting it is not a safe repair. A missing
file or absent shared row still means first boot for a new process, so external
backups and storage attachment checks remain necessary. This validation does not
detect a syntactically valid replacement with different settings, or implement
live shared-writer refresh and conflict resolution.

## Administrative writes refused by a standby

A standby control plane refuses routes requiring a write permission with HTTP
409 before resolving credentials, tenant context or request contents. Retry
through the active management server. The refusal does not mean that a token is
invalid, and it does not authorize or apply the requested change.

The refusing node records `admin_write_refused_on_standby` in its local audit
log. In **Logs & Audit → Logs → Admin audit**, search for this event and open
**Details → View raw**. `result=refused` and `reason=not_leader` describe the
routing decision. `authentication=not_evaluated` and
`request_tenant=not_evaluated` explain why no actor, session or target ID is
attached. The row uses the node's configured tenant scope with
`audit_scope=node`; it is not attributed to a tenant named by the request.
The registered permission and status are recorded, without request bodies,
credentials, URLs, user-agent strings or forwarded addresses.

This early refusal does not call the audit outbox synchronously. The local
writer's configured append hooks still apply; local recording does not guarantee
delivery to another node or a webhook. Inspect the refusing node's logs if the
active management server does not show the event. A primary write failure is
reported through the writer health and process error log; an unconfigured writer
is reported in the process error log. Neither failure permits the request.

The first refusal for each registered permission is recorded immediately. Further
refusals share a per-node, per-permission write budget of one attempt per minute.
They are accumulated into a summary with `aggregation=permission_window`,
`request_count`, `first_seen`, `last_seen` and `interval_seconds=60`. The row's
`timestamp` is its emission time. Sum `request_count` to count refused requests;
the number of audit rows is not the number of requests. Individual request IDs
and timestamps inside a summary are not retained.

The running server checks pending summaries every five seconds, including when
requests stop or the node becomes leader. A due summary is normally attempted
within 60–65 seconds of the preceding attempt; slow storage or append hooks can
delay this. Normal process return attempts a final flush and waits for it. The
counters and budgets reset on restart. They are held in memory: a crash, forced
kill, fatal exit or requests still in flight at process exit can lose an unflushed
tail. They are not a durable queue.

A failed append consumes the same budget, so filesystem or hook failures cannot
produce an error message for every request. Writer health and a bounded process
error report expose the unconfirmed summary's count. Failed batches are not
replayed automatically: a hook failure may follow a successful local append,
and replay could double-count those requests. An unconfigured writer is reported
in the process log with the same budget. Refusals always remain HTTP 409.

Only server-registered permissions create counters; source addresses, paths and
credentials cannot create new aggregation keys. Existing JSONL rotation/retention
and optional request-rate limiting still apply. The latter is disabled by default;
this audit budget is always enabled and does not change request admission. Local
storage and append hooks can still delay request completion. These records do not
claim that every incoming HTTP request, read refusal or upstream rate-limit
rejection is audited, or that local append is a crash-durable transaction.


## Finding deployment operation audits

In **Logs & Audit → Logs → Admin audit**, a deployment operator outside a selected
organization can choose **Audit scope → Deployment operations**. This reads only
the reserved deployment audit namespace. It does not combine customer logs.
**Current organization** remains the default and shows the authenticated
organization's records; entering an organization uses that selected organization's
records and removes the deployment option. Access requires the route's log-read
permission and the operator's cross-organization administrative authority.

For example, publishing a deployment-wide agent release records the publication
and activation events under `deployment`, while the common HTTP request audit
belongs to the acting administrator's organization. Search each scope separately
and use **Details → View raw** to inspect the actor, target, result and timestamp.
Changing the stream or audit scope clears the previous search filters. A failed
or unverifiable deployment response shows Retry instead of an empty result; late
responses from a previous scope or departed page are discarded. Update the Console
and control plane together: an older server may ignore the new scope parameter,
and the updated Console refuses to label that tenant response as deployment data.

The search API accepts `audit_scope=deployment` on `GET /admin/logs/audit`.
The same explicit scope and authorization apply to the bounded NDJSON preview at
`GET /admin/logs/audit/export`, with its separate preview-export permission.
Omitting `audit_scope`, or using `tenant`, preserves the ordinary tenant-scoped
query. Invalid, empty or repeated scope values return 400. Deployment scope on
another stream returns 400; a customer, an operator without cross-organization
authority, or an operator currently inside an organization receives 403.

This selector applies to hot-log search and the bounded preview API. It does not
change queued archive exports, legal hold, retention or audit-chain verification;
those operations retain their existing scope. Search results describe records
available to the queried management server, not proof of complete collection from
every region. Reading these records does not itself create a configuration-change
audit event.


### Publication in progress and unconfirmed results

The agent publication form belongs to the verified page and publication scope
that opened it. During package verification, publication and upload, its inputs,
Cancel, Escape and backdrop dismissal are locked. Opening the form again does not
start a second operation. Leaving the page or changing organization closes the
form and suppresses later UI completion; it cannot undo a write already sent.
The Console checks that context again after each asynchronous step and sends an
explicit scope pin to the control plane for both publication and package upload.

HTTP success alone is insufficient. Before sending the package, the Console checks
the acknowledged organization, target, version, package digest/size and manifest
hash. The upload carries that same manifest hash, so a superseded manifest can be
refused before the package is read or stored. Success requires a matching upload
acknowledgement and confirmation that this manifest is active in the catalogue.
An already-active upload can succeed with `activated=false` and `active=true`;
`activated` describes this request's promotion, not the catalogue's current state.
Neither field establishes that endpoints have installed the release.

On a failed or unverifiable response, the form retains its selected files and
entered values and displays a persistent message. Publication or activation may
already have happened; a failed acknowledgement does not roll back saved data.

When publication was confirmed but upload was not, the fields remain locked and
the button becomes **Retry package**. It sends the original package with the same
acknowledged manifest hash, without hashing, signing or publishing again. Cancel
is available between attempts. If another publication has replaced that manifest,
the existing hash pin rejects the stale upload; cancel and reload before making
another change. A verified publication followed by an uncertain upload is not
automatically described as still pending, and an already-active upload may be
confirmed by the retry.

When publication itself could not be confirmed, no trusted manifest hash is
available for upload-only resume. The fields unlock and **Publish** remains an
explicit publication retry. Cancel and reload to reconcile saved state before
changing the release. Closing the form or leaving the page discards its remembered
upload stage; it does not cancel server-side changes. No stage is saved across
browser reloads. Retries can add audit records and are not exactly-once operations.

`POST`/`PUT /admin/agent-updates` and `PUT /admin/agent-update-artifact` accept
`expected_tenant_id`; artifact upload also accepts `expected_manifest_sha256`.
These optional parameters bind a request, not its authority. Mismatched or repeated
pins return 409 before the corresponding side effects. Authentication and route
permissions still run first. Existing clients may omit them. Update the control
plane before or with the Console: older acknowledgements without the new scope,
package and active-state fields are reported as unconfirmed.

These checks do not serialize concurrent administrators, make the two requests a
transaction, provide shared-writer conflict resolution, or confirm delivery to
every Edge. Publication, package storage, activation and their audit records remain
separate operations. Reconcile an unresolved attempt against the catalogue and
stored package before changing the offered release.

### Downloading a published agent package

**Download** retrieves the active release shown in the catalogue, even when a newer
manifest is still waiting for its package. The Console pins the verified publication
scope and active manifest hash. Before saving a file, it checks the response scope,
version and manifest hash, then compares the actual package size and SHA-256 with
that manifest. Partial responses, redirects and unverifiable packages are refused.
Only one download per row can be pending. Leaving or reloading the page, or changing
the organization while a request or hash check is pending, discards the old result.

The error identifies the next action:

- A scope mismatch requires checking the selected organization before reloading.
- A release version or manifest mismatch requires reloading the release list;
  another administrator may have replaced the active release.
- A package size or SHA-256 mismatch blocks the download. Do not distribute that
  package. Ask the deployment operator to investigate the stored artifact and its
  delivery path. Reloading alone does not repair inconsistent bytes.
- A failed transfer or an unavailable browser integrity check is reported separately;
  neither establishes that the stored package is corrupt.

The Console does not save newly returned bytes under an older release's filename.
These messages do not automatically quarantine an artifact, change the rollout plan,
or add an audit record. An operator must investigate a reported byte mismatch.

`GET /admin/agent-update-artifact` retains its tenant-effective default for bundle
and replication clients. The Console adds `artifact_scope=publication`, with
`expected_tenant_id` and `expected_manifest_sha256` as consistency pins. These
parameters do not grant access or select an arbitrary tenant. The publication view
is resolved from the authenticated operator and selected organization. Successful
responses include `X-Dsse-Agent-Update-Scope`,
`X-Dsse-Agent-Update-Manifest-SHA256`, `X-Dsse-Agent-Update-Version` and
`Cache-Control: no-store`. Existing Range clients remain supported; the Console
requires a complete HTTP 200 response. Update the control plane before or with the
Console: a response missing the verification headers is not saved.

These checks establish consistency with the displayed manifest, not native installer
signature validation, successful installation, delivery to every region, or concurrent
writer serialization. The control plane verifies the manifest envelope; the browser
does not independently verify its signature. Normal downloads do not create write
audit records.


### Reading the connector program catalogue

Agent Releases and Sites → Add connector read the control plane's shared programs
and the current organization's overrides. A successful empty response means no
programs are currently listed. An unavailable or malformed response shows an error
and **Retry** instead of advising that programs must be uploaded. Retrying this list
inside Add connector does not issue a new enrollment profile or rotate its key.

The server rejects incomplete catalogue reads with HTTP 503: unreadable scope
storage, malformed target metadata, missing program files and size mismatches do
not become an empty or partial list. A broken organization override is not silently
replaced by the shared program in that list. The error omits local storage paths.
The Console also validates the response count and each entry, and discards reads
from departed pages, sessions, control-plane addresses or organization selections.

New, absent scope directories can produce a valid empty catalogue. This read does
not remember whether a missing directory existed before a process restart, hash
every stored program or make publication atomic with its metadata. It does not
change the raw download endpoint's lookup rules. Verify program bytes separately;
catalogue validation is not acceptance of a native installer or a running connector.


Successful Site create/update, delete and enrollment-command audit entries include
`actor_user_id` from the authenticated administrator principal. When an operator
works inside another organization, the event belongs to that target organization
and still names the requesting principal. API tokens use the principal resolved by
the authentication layer; this identifies the credential owner, not a separately
verified person holding the token. Calls without a resolved principal retain a null
actor. Bootstrap secrets and their hashes are not added to these audit records,
and historical records with missing actors are not backfilled.

### Verifying a connector program download

The Console checks the downloaded program's size and SHA-256 against the displayed catalogue before offering it as a file. Partial responses and redirects are refused. A mismatch can indicate damaged storage or delivery, or a publication change since the list was loaded: do not distribute the rejected program; ask the deployment operator to investigate. If browser hashing is unavailable, the Console refuses to save without claiming corruption. Connection/access failures can be retried after reloading the list.

The program selection is locked during download. Closing the dialog or changing the active organization, credentials or authority discards late results. Download retries do not issue enrollment credentials; opening Add connector again remains a separate enrollment operation. This browser check does not add a publisher signature, make catalogue publication atomic, or verify programs fetched directly outside the Console. Server response scope pins and download lookup behavior are unchanged.

### Confirming a connector program upload

In Agent Releases, the Connector programs card names the tenant that will receive the upload. In the deployment view this is the operator’s own tenant, not every tenant. To publish for a customer, choose Exit tenant if already managing another tenant, open Tenants, choose Manage for that customer, and then open Agent Releases. The card is available to operators in either view; customer administrators still obtain programs through Sites.

An upload replaces only that tenant’s program for the chosen platform and architecture. Other tenants and shared deployment programs are unchanged. The catalogue combines shared programs with this tenant’s replacements, with a replacement taking precedence for the same target. The displayed tenant comes from the verified tenant read; it does not add a server-enforced scope pin to this API.

Connector uploads hold the file, target and build fixed while reading, hashing and sending. The Console only clears the selected file after HTTP 200 metadata confirms the submitted target, filename, size, digest and build. A failed or incomplete acknowledgement may follow a completed save: the Console retains the input, shows a persistent uncertainty notice and refreshes only the catalogue for inspection. Choose Add it deliberately to retry; each retry is another audited upload. A preparation failure means nothing was sent. Reloading or leaving the page discards the form, and leaving after dispatch cannot undo a write already sent.

These checks do not change the server's authenticated-tenant override destination, shared seeded programs, or publication authorization. The existing response contains no tenant scope pin. Confirmed metadata is not an atomic publication transaction or protection against a later concurrent writer. Existing common API audits record the operation and principal; the publication detail event described below identifies the saved program.

### Connector publication audit details

With an audit writer configured, completion of a connector program's byte and metadata saves emits `admin_connector_program_published`. It names the authenticated principal, target tenant and `platform/arch`, with the saved build, filename, publication time, verified SHA-256 and byte count. `publication_scope: tenant_override` identifies the actual destination; this event does not mean the shared deployment seed changed. Cross-tenant operations also retain the operator’s home-tenant attribution. Raw program bytes, credentials, arbitrary request headers and storage paths are excluded. Build and filename are retained as publication metadata supplied by the operator.

The existing common API audit remains separate. Rejected uploads and metadata-write failures do not emit a publication-success detail, and reads do not emit publication events. An explicit retry is a new publication and a new audit record. Records use the primary audit writer and then the existing outbox mirror. This is best-effort audit recording: audit failure does not roll back the saved program or change the successful upload response. Consult audit-writer health for primary failures; outbox delivery and successful writes are not a single transaction. Older publications are not backfilled.


### Reading rollout group memberships

Agent Releases verifies the enrolled-device inventory before offering a change to rollout order. The read names the verified tenant, and the response must be HTTP 200 with the expected inventory schema, tenant and well-formed device identities, tenant ownership and group names. An unavailable or inconsistent response shows a retry notice and disables only the rollout-order editor. Existing saved order remains visible; maintenance-window and version controls still depend on their own verified reads.

Retry reloads the page’s read-only data; it does not save a rollout plan. A verified empty list is described as an inventory snapshot with no reported group assignments. These hints describe the enrollment inventory, not live endpoint telemetry or proof that a group currently has connected devices. Special group names are retained and repeated names are listed once. Obsolete reads after navigation, a newer render, tenant, session, authority or API-token changes are discarded. This does not add a new server permission, a storage snapshot transaction, or a concurrency lock between the inventory and a later schedule save.

## Editing site settings

The Sites editor preserves a site's existing routing namespace and HA policy when
you change its display name, region, deployment type, or expected connector count.
These two hidden settings are not editable in this form. The server continues to
manage enrollment credentials and creation timestamps.

Enter the expected connector count using decimal digits for a non-negative whole
number (at most 9007199254740991). Fractions, negative values, and exponent notation
are rejected before saving. Blank or `0` clears the target; reopening an existing
site displays `0` for no target. The count is a configured target, not evidence
that connectors are online or that failover has been tested.

Edits use the values loaded when the editor opened. Reload before editing if another
administrator has changed the site; the editor does not detect concurrent writes.
