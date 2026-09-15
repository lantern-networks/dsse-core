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
