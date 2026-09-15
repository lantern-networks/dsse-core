# Service accounts in the Console

Open **People & Service Accounts → Service accounts** in the intended organization.
The tab lists accounts, their recorded owner, risk assessment, status and account
boundary. Search matches account names, IDs, owners and types. If a required
account, risk or policy lookup fails, the tab displays an error with **Retry**;
an unavailable lookup does not mean that no boundary exists.

Use **Add account** to enter an ID, name, type and owner ID. Select **Active** or
**Suspended**. This form registers account metadata; it does not issue a credential.
Choose a new ID: submitting an existing ID updates that account in the same
organization. The form does not provide a separate edit or delete workflow, and
the owner field does not validate that the person exists in the directory.

An optional comma-separated tool list creates an account policy named
`pol-agent-<account ID>`. An ID containing `/` cannot be used with this boundary.
The list describes that policy's tool boundary, not the complete access decision.
Policy selection, other rules, grants and runtime identity checks still apply.
Verify the effective decision and delivery to each Edge before using the account.

## Save outcomes

The account and its boundary are separate writes. If the account saves but the
boundary cannot be confirmed, the form retains the saved account values and offers
**Retry boundary**. This retries the original boundary without resubmitting the
account. Review and resolve the warning before using the account. Closing a pending
form may leave an accepted account behind; closing the dialog does not cancel an
already submitted server request. Reload its state before retrying an uncertain
operation. Notices in the tab are not a durable work queue and do not survive a
full browser reload.

For a configured persistent store, a rejected account or policy save returns an
error before changing live configuration or its generation. Partial physical writes
or ambiguous database commits still require storage-level recovery. In-memory
stores remain non-durable. Saved-without-atomicity warnings are logged by these
stores and still accepted; this tab does not yet show a separate durability badge.

In **Logs & Audit**, successful account and boundary writes appear separately as
`non_human_identity_upserted` and `admin_policy_upserted`. The policy record includes
the acting administrator, target policy and tool count; it omits the tool values.
Rejected writes appear in the common administrative audit stream. A successful
configuration audit does not prove delivery or enforcement on every Edge.

Policy changes and Network Extension snapshot publication are separate steps. If
publication fails after the policy store accepts a change, the API returns HTTP
500 with `status: "partial"`, `applied: true`, the tenant and policy IDs, and
`ne_snapshot_status: "unconfirmed"`. The Console explains that the boundary is
already applied on the administration server and offers **Retry boundary**.
This outcome does not mean that nothing changed: some snapshot files may have
been written while others still contain their previous contents. Verify the
configuration on the endpoints before using the account.

Accepted policy updates and removals are audited as `admin_policy_upserted` and
`admin_policy_deleted`. Their result is `partial` when snapshot publication is
unconfirmed; the common administrative record also retains the HTTP error. The
domain record identifies the administrator, tenant, policy and operation, with
`applied` and `ne_snapshot_status`. A `published` snapshot status describes the
local publisher's successful return, not endpoint delivery; `not_requested` means
no publisher was configured.

For deletion, `applied` describes removal from the live store. The file-backed
delete path still uses best-effort persistence, so this flag does not guarantee
durability. Reload the policy before retrying a partial deletion: it may already
be absent, in which case another DELETE returns 404 and does not retry snapshot
publication. Reconcile the deployment's snapshot output separately. Do not
recreate a removed policy merely to retry publication.

## File-store upgrade

Account snapshots are indexed by tenant and account ID. On loading an older
snapshot, the current writer rebuilds this index from each saved record's tenant
and ID, and writes the new keys on the next save. Duplicate or invalid record keys
are refused. This cannot restore accounts already overwritten by an older writer;
recover those from a verified backup or re-register them deliberately.

Back up the account store and upgrade all processes that write it together. Do not
mix old and new writers against the same snapshot or simply downgrade the binary:
older writers index new updates by bare ID and cannot maintain the tenant boundary.
PostgreSQL account rows already use a composite tenant/ID key; this file-index
change does not require a new SQL migration.

The tab requests up to 1,000 policies and refuses a truncated result rather than
asserting that omitted accounts have no boundary. Larger catalogs need a paginated
workflow. Complete role coverage, concurrent administration and independent
control-plane/Edge acceptance remain separate checks.

## Human approvals shown in Activity

**Activity** lists recorded approval outcomes for the current organization. It does
not perform the human approval ceremony. The Admin API exposes the corresponding
`/admin/human-approval-events` operations. Store lookups and revocation use both the
organization and approval ID, so identical IDs in different organizations remain separate.

An upsert is saved before publication to local lookups. A rejected save returns HTTP
500; that candidate is not activated in this process. An ambiguous storage error does
not establish that the storage backend rolled back. For explicit revocation of an
existing approval, use `POST /admin/human-approval-events/{approval_id}/revoke`.
That operation keeps the approval revoked locally even if saving fails. The failure
returns HTTP 500 with `status: "partial"`, `applied: true`, the organization/approval
IDs and `persistence: "unconfirmed"`. Restore the persistence service and retry the
same revoke before restarting; otherwise the older saved approval can return.
The retry attempts saving even when Activity already displays **revoked**, and keeps
the original revocation reason.

**Logs & Audit** records these incomplete revocations as `partial`, naming the
administrator, organization and approval, without including the supplied reason text.
Accepted upserts and revocations also name the administrator. Activity's decision badge
reports the current local outcome; it does not attest to persistence or fleet delivery.
The Admin API does not send approval notifications or distribute outcomes to other servers.

Approval snapshots, whether files or shared JSON blobs, now use organization-and-ID
keys. Back up the store and upgrade all writers together. The loader accepts valid old
ID keys and reindexes them from record attribution; invalid/conflicting entries stop
loading instead of being discarded. Old writers must not share an upgraded snapshot,
and downgrading the binary alone is unsupported. Previously overwritten records need a
verified backup or deliberate re-registration. Empty/in-memory stores, non-atomic save
warnings, tenant-removal persistence and multiple writers remain separate operational
limits. The index change does not establish multi-writer consistency.

## Approval and delegation capacity

Human approvals and delegated grants retain their existing records, including explicit
revoked, denied or expired outcomes. New records do not evict old authorization state.
When either store reaches its limit, a new organization-and-ID pair returns HTTP 503
with a `store capacity reached; existing records retained` error. Existing-ID updates
and revocations remain possible, subject to their normal validation and storage checks.
A terminal record cannot be reactivated by sending the same ID with a fresh expiry.

`DSSE_EVENT_STORE_CAPACITY` defaults to 50,000 records **per store**, shared across the
organizations on that process. This setting also controls inspection history, which
still uses FIFO retention. It is not a per-organization quota. A value of zero or less
removes the limit and needs memory planning.

Approval and delegation records are not automatically pruned when they expire. Inspect
store counts, then increase the configured capacity on the control plane and affected
Edges as needed, preserving the existing snapshots. A restart with a lower limit loads
all saved records and refuses new IDs until there is room; it does not truncate saved
revocations. Do not delete authorization snapshots to make room. Backups and durable
storage remain necessary: an empty in-memory store cannot retain revocations across a
restart. This change does not recover records already lost to earlier eviction.

If an Edge rejects a delegated grant during configuration synchronization, that
configuration generation stays unapplied and is retried. Other grants in that bundle,
including revocations of retained IDs, are still attempted. Some sections can already
have changed; a synchronization error is not a rollback. Check fleet synchronization
status after increasing capacity or repairing storage. Control-plane acceptance alone
does not confirm every Edge has adopted a change.
