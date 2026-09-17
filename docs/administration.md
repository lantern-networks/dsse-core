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

A standby returns HTTP 409 for the revocation feed and the Console's connection
block status. Edges retain their last applied set when that feed is unavailable.
Devices displays a status error with Retry, rather than a successful empty list.
After promotion succeeds, reload the Console and check the Edge synchronization
status separately. A local administrator response is still not a fleet receipt.

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
