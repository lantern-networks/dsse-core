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
