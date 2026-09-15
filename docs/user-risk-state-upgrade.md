# User risk state upgrades

Manual user risk is scoped to a directory identity in one organization. A user's
risk must not mark a device or another organization's user that happens to have the
same ID. In the Console, use **People & Service Accounts → People → Risk** after
confirming the organization context. Medium, High, Critical and Normal update the
selected person's risk. A risk signal affects access only through the configured
policies; changing a signal does not itself revoke grants.

## Storage and compatibility

The durable overlay now uses `high_risk_overlay_state.v2`. It keeps device marks
in `devices` and user marks in `users`. Each user entry includes its tenant,
canonical directory ID, severity and subject aliases from that directory record.
The decision path matches these aliases only within the request's authenticated
tenant. A stronger user signal is not hidden by a weaker device overlay signal.

The control plane's `/admin/revocations` feed declares `user_risk_version: 1` and
carries typed `user_risk` entries separately from device `high_risk` entries.
An explicit authoritative empty user set releases cached user marks. Invalid
entries or an unsupported version are rejected before replacing admission or
device state. A feed without the user version preserves existing typed user
marks; it cannot establish current user-risk state on a newly started Edge.

**Use a coordinated upgrade of all control planes and Edges. Mixed revisions and
rolling upgrade are not supported for this format transition.** An older binary
cannot enforce the new user entries. Do not run it against an upgraded shared
store, or use it as a fallback control plane. Do not downgrade by simply replacing
the executable or image.

## Before starting the new revision

1. Schedule a maintenance window and record each node's current revision and
   store configuration. Stop risk edits and the old control-plane/Edge writers.
2. Take consistent backups of the risk overlay, enrolled inventory and identity
   directory, using the backing stores' supported backup procedures. Keep their
   matching software revision. Protect these backups as private operational data.
3. Confirm that the new process can read the complete enrolled inventory and
   identity directory, including all organizations. A partial directory export or
   only the first Console page is not enough for attribution.
4. Start the new authority with those stores. Before starting its feed worker or
   serving requests, it classifies every legacy v1 ID against both inventories.
   An ID matching exactly one person and no device becomes a typed user mark.
   An ID matching only a device remains a device mark. The process saves the
   complete converted snapshot before publishing it.
5. Review startup logs. Unreadable, malformed or unsupported risk state stops
   startup. A legacy ID with multiple possible owners, both a person and a device,
   or no known owner also stops startup without saving a guessed assignment.
6. Start compatible Edges, check risk synchronization status, then verify the
   selected user's severity in the Console and a policy decision through each
   region. Include another tenant with the same synthetic user ID and a device
   with that ID in the acceptance check. Clear the test risk explicitly when done.

If attribution fails, preserve the reported snapshot and inspect that ID in the
complete directory and inventory. Do not delete the risk file or distribute the
mark to every possible owner. Establish which entity the original operator
intended before correcting the source records and retrying. If that intent cannot
be established, the upgrade remains blocked. Any rollback requires the matching
pre-upgrade stores and software together in a controlled maintenance window;
restoring an old risk snapshot can lose later operator changes.

## Verify save results and audit

The user-risk API confirms the canonical user ID and tenant. A rejected save
leaves the live user-risk map and generation unchanged. The Console retains an
error and an explicit retry action; a transport failure may mean that a write
already reached the server. Reload its state before retrying.

When a store accepts a write without confirming its durability or atomicity,
the response includes `not_stored_durably`. The Console keeps a visible warning,
and `user_risk_changed` records the accepted operation as `partial`. A confirmed
save records `success`. These records name the actor, tenant, canonical target,
severity and persistence warning, without copying the signal body or subject
aliases. Rejected HTTP writes appear in the common administrative audit stream.

Check these records in **Logs & Audit** and confirm state after restart. A
successful save is not evidence that every Edge has received it. Store errors
with ambiguous commits or partial physical writes require backing-store recovery;
the live-state guarantee does not prove that the durable bytes were unchanged.

Subject aliases are captured when the user mark is written. After an identity's
subject/email changes, review and reapply its risk to refresh those aliases.
Directory pagination, every administrator role, shared-store writer concurrency
and independent regional failover require their own acceptance checks.
