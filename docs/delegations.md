# Delegations and activity

Open **People & Service Accounts → Delegations** in the intended organization.
Use **Add delegation** to record an account acting for a person. Enter a new grant
ID, the service account ID, the person ID and, optionally, a comma-separated list
of tools. The form records delegation metadata; it does not issue a credential or
complete a human approval flow. Submitting an existing active grant ID updates it
within that organization. Revoked grants cannot be reactivated by this form.

An empty expiry uses the server's default lifetime, currently 30 minutes. Check
the returned expiry in the list. An empty tool list adds no grant-specific tool
restriction; identity, policy, application and other runtime checks still apply.
An active record whose expiry has passed is displayed as **expired**.

Search matches the grant ID, account, person or application. The tab requests up
to 1,000 records and shows the returned/total counts when truncated; search covers
the loaded records. Required grant and organization lookups must succeed before
the editing controls are displayed. Use **Retry** after resolving a read error.

## Saving and revoking

Select **Revoke** and confirm to revoke a grant. Creation advances configuration generation after the configured store accepts the
save. A rejected creation retains the previous live state. Revocation is applied
locally even when saving fails; the response marks persistence as unconfirmed.
Retry before restarting, and do not assume another Edge has received that denial. If a request is interrupted or its result cannot be verified, reload
the list before retrying: the server may already have applied it. Closing a pending
dialog does not cancel the request. In-page warnings do not survive a full reload.

In **Logs & Audit**, successful writes produce
`admin_delegated_access_grant_upserted` or `admin_delegated_access_grant_revoked`,
including the acting administrator, tenant, target grant and resulting status.
Rejected saves produce a common administrative error record without a success
domain record. Generation changes let bundle synchronization detect a change;
they do not prove delivery to an Edge or termination of an existing session.
Verify those effects against your deployment's enforcement path.

In-memory stores remain non-durable. A store reporting saved-without-atomicity is
still accepted and logged; this tab has no separate durability indicator. Partial
physical writes and ambiguous database commits require storage-level recovery.
Capacity limits active grants across tenants. Existing authorization and revocation
records are retained; accepting a new grant does not evict old records. Received
control-plane snapshots are not restricted by the local admission capacity.

## Snapshot upgrade

Grant snapshots use tenant plus grant ID as their index. Loading an older JSON
snapshot rebuilds this index from each record's tenant and ID; the next successful
save writes the new index. Invalid or duplicate record keys are refused. The old
format did not persist insertion order, so loading uses a deterministic fallback
order. This migration cannot restore records already overwritten by an old writer.
Recover those from a verified backup or register them deliberately.

Back up the store and update all writers together. Do not mix old and new writers
or downgrade against a converted snapshot. This applies both to files and to JSON
snapshots in the shared database; no SQL schema migration is required for this
index change. Use the shared-store update path for concurrent writers. Revocation through the
Edge connector-facing endpoint currently remains local: CP reporting and propagation
to other Edges are still outstanding. Revoke through the control-plane administration
path when the change must reach the fleet, and verify receipt on each Edge.

## Activity

The **Activity** tab reads recorded tool calls and human approval decisions. Its
approval column uses the recorded `approval_result`. An unavailable or malformed
source produces an error with **Retry**, not an empty history. Each list displays
the returned/total counts when truncated. These are recent, limited lists rather
than a complete audit export. An approval record is evidence of the stored decision;
it does not by itself establish that a tool was run or that an Edge enforced it.
