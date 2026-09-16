# Egress policy: Internet Access

**Internet Access** controls traffic leaving a customer's devices for Internet
destinations. An access decision, TLS inspection, and DLP are separate controls.
The optional egress broker changes the upstream HTTP/TLS implementation; it is
not the policy engine and is not required by the standard generated deployment.
Standard inspected egress uses Go HTTP/TLS.

This guide describes the current experimental source. Read it with
[Organizations](organizations.md), [IdP integration](idp.md), and [PKI](pki.md).
Behavior and configuration may change between revisions.

## Default behavior and rule order

A new customer starts with an explicit **allow and inspect** Internet Access rule.
Narrow that rule as part of setup. The evaluator's default-deny behavior does not
override a matching allow rule. Internet Access has no East-West OBSERVE stage.

Active authored rules compile into the effective policy set together with other
configured policies. **Lower priority numbers win**; use distinct priorities for
overlapping rules. Disabling a rule removes its authored contribution after the
new configuration is applied, which can expose a broader allow below it. Check
the effective list and a real decision instead of assuming deletion means deny.

## What a rule contains

| Control | Meaning |
|---|---|
| Source | Any, catalog device/group, or supported person/IdP-group/agent selectors |
| Destination | Any or named catalog endpoint/group that resolves to destination addresses |
| Service | Destination port scope; no service means any port |
| Priority | Evaluation order; smaller number first |
| Access | Allow, Deny, or Authenticate |
| Contents | Inspect (decrypt) or Do not inspect it |
| Sign-in requirements | Provider and assurance settings for Authenticate; see the current [IdP limits](idp.md#authentication-strength-and-current-limits) |
| DLP policy | Reusable DLP policy applied to inspected traffic |
| Risk threshold | Applies the rule only when the subject's current risk meets the selected threshold |

An unresolved source does not become Any. A destination that resolves to nothing
is shown as **matches nothing** and cannot enforce a deny for that destination.
Repair the catalog reference. An unavailable or invalid named service is shown
as **service unavailable**. Its access rule matches no traffic: it cannot grant
access, deny traffic, or require authentication until the service is repaired.
It does not fall back to HTTPS. Other matching rules and the default still apply.

Named services retain each TCP/UDP and port combination. For example, TCP/22 +
UDP/443 does not authorize TCP/443 or UDP/22. **Any** service (no service selected)
intentionally omits both restrictions. Service writes and snapshot loading
normalize protocol case and surrounding whitespace, and reject protocols other
than TCP/UDP or ports outside 1–65535. Invalid persisted service definitions
must be repaired before the catalog can load; loading does not rewrite the file.
The inspection host compiler requires the named service to contain
TCP/443. An unresolved service adds neither an inspection target nor a bypass.

Egress compiles person and IdP-group selectors into user identity conditions and
device selectors into device conditions. When different source selector kinds
are combined, they are alternatives (OR), not a requirement to satisfy all of
them. Whether user/group information is present depends on the authenticated
traffic path; selecting a group does not itself synchronize an IdP directory.

## Create and verify a rule

1. Enter the customer organization and open **Internet Access → + Add rule**.
2. Select a narrow source and destination from the catalog. For a new destination,
   create or select its named network endpoint; verify the FQDN/IP and service port.
3. Choose a priority ahead of any broader matching rule, then choose **Access**.
   Start with a disposable test target so the result is unambiguous.
4. Select **Contents**. For inspected HTTPS, first establish that the test device
   trusts the customer's inspection root and the application accepts inspection.
5. If needed, select an [IdP](idp.md) for Authenticate or a policy from **DLP Policies**
   for content inspection. Save the rule and confirm the effective configuration
   on the serving Edge.
6. Start new connections from an included and an excluded source, to the target
   and a control destination. Confirm both the application result and the access
   decision/inspection records.

An example sequence, using endpoints and devices you control:

| Test rule | Expected result to verify |
|---|---|
| Selected device → test HTTPS endpoint, Deny, priority 10 | New connection denied; another intended allowed destination still works |
| Same target, Allow + Inspect | HTTPS succeeds with the intended inspection chain |
| Same target, Authenticate + required ACR | Baseline grant cannot satisfy the flow; required ACR can, subject to the documented grant scope limits |
| Same target, Allow + Inspect + a DLP policy | Synthetic matching upload is handled by the configured DLP action; ordinary upload succeeds |

These are examples to configure and measure, not a statement that this release
has passed those tests. A preview is useful but does not prove steering, TLS trust,
content visibility, or enforcement on a real endpoint.

## Inspection and bypass are not the access decision

Allow does not require leaving content uninspected. Authenticate does not itself
enable DLP. Deny does not forward traffic, and the rule validator rejects
Deny combined with inspection bypass.

**Authored TLS inspection preserves tenant and device source scope.** Any-source
rules contribute shared host patterns; a catalog device or device group contributes
patterns only for its resolved device identities. The TLS selector uses the
transport-authenticated tenant and device identity, never a self-reported OS user.
An empty or unresolved source does not become Any. Both inspect and bypass host
selection require Service=Any or a service containing TCP/443; SSH, UDP-only and
unresolved named services do not change TCP/443 inspection.

Person, IdP-group and agent source selectors require identity context that is not
available to this pre-TLS selector. They do not create shared or device inspection
exceptions; the Console shows that limitation. Their separate access-policy
conditions still apply. If a rule mixes device and identity selectors, only the
resolved device branch contributes to TLS selection.

Risk conditions and authored access priority are not yet evaluated by this host
projection. Inspect rules do not cancel a separate matching bypass merely by
having higher access priority. Any destination is not currently expanded by this
inspection projection. Review device-profile, static and approved certificate-pin
exclusions as well; these controls are separate from source-scoped authored rules.

Inspection Settings and the bypass-hosts API list shared host patterns, with the
posture response flagging additional device-scoped rules. A destination-only
Policy decision check reports **Depends on the device** when a device rule can
change the inspection result. Confirm from included and excluded source devices;
a destination-only preview cannot supply an authenticated source identity.

A bypassed encrypted connection does not expose its plaintext to HTTP DLP.
Protocols such as SSH are not converted into inspectable HTTP by choosing Inspect.
The standard native TLS interception selector also targets port 443; a rule for
another port does not itself extend that interception capability.
Applications using their own trust bundles or certificate pinning can reject TLS
inspection even when the OS trusts the root. Verify with that application.

To enable content controls, create a reusable policy under **DLP Policies**, choose
detectors and the match action, and attach it to an inspected Internet Access rule.
Use synthetic data for blocked and allowed upload tests. Account restrictions for
supported SaaS services are a separate feature in
[SaaS tenant restriction](saas-tenant-restriction.md).

## Built-in bypass overrides

In **Built-in Bypass List**, **Force-inspect** and **Disable** remove an entry's
curated bypass for the selected organization. **Restore default** removes that
override. These controls change the catalog's contribution; they do not override
other bypass rules or force inspection when the deployment posture excludes a host.
Test new connections and check the effective inspection selection.

With override persistence configured, changes are saved before the live selection
is rebuilt. A storage failure returns an error, leaves the current live selection
in place, and records the administration request as failed. Repair storage, reload
the page and retry the intended change. An error can occur after storage was
written, so restarting is not a substitute for a successful retry. Without
persistence, overrides last only for the running process.

The common administration audit records the actor, organization, request path and
result. It does not currently retain the override's previous/new mode or reason.
For a successful retry, verify the saved override and the effective selection in
addition to the audit result. Signed catalog feed updates are a separate operation.

### Signed catalog updates

Only the deployment operator, outside an entered customer organization, can apply
or roll back the signed feed. Customer administrators can override entries in the
current effective catalog, including entries supplied only by a feed. An override
is keyed by entry ID: it has no effect while that ID is absent, and applies again
if a later feed or rollback brings the ID back.

Apply checks the configured trusted signing key, signature, checksum and expiry.
A version must be newer than the currently applied version; use **Roll back** to
select an available historical version. The history retains at most 20 applied
records. A previously applied feed remains in use after expiry and is shown as
stale; this is distinct from submitting a new expired feed, which is rejected.

With a feed state path configured, apply and rollback save the catalog and history
before changing the current selection. Saving uses staged replacement and flushes.
A storage error leaves live state unchanged and permits retry, but the destination
may already have been replaced before a flush error. Repair storage and retry the
intended operation before restarting or changing the state path. Keep a backup
for recovery. Mount the containing directory rather than relying on replacement of
a bind-mounted file. Without a state path, updates are in memory only.

This confirms a local update, not its delivery to other nodes. Check the effective
catalog and inspection selection on every serving Edge. The common mutation audit
records actor, organization, request path and result; it is not a feed-content diff.


## Save and verify inspection defaults

**Inspection Settings** configures defaults for the whole deployment. Only the
operator organization, outside a customer operation context, can change the mode,
host allowlist, sign-in/AI presets and operating-system bypass switch. Customer
administrators can view the defaults and manage their own Internet Access rules.
An Edge that pulls configuration from a control plane rejects local writes.

Select the required sign-in and AI presets, save the list, then choose the desired
mode. Under **Inspect only what I list**, destinations absent from the allowlist
are not decrypted. Removing a service bypass rule does not add that service to the
allowlist or override other exclusions. **No service bypass** describes that
service's rule state; it is not proof that traffic is being inspected.

Deployment defaults and tenant exceptions have separate scopes. Authored
inspection/bypass destinations and curated-catalog overrides apply to their owning
tenant. The serving Edge selects a complete host set using the authenticated
connection's tenant; updating another tenant does not replace that selection.
Changing deployment mode rebuilds all tenant selections together. Deleting a last
rule removes its contribution, including after restart or a rule-bundle refresh.

Inspection Settings, Policy decision check and the bypass-host listing show the
effective host selection for the current customer context. Their host lists do not
include other customers' exceptions. The `scope=deployment` field describes the
shared posture settings; `intercept_hosts` and `effective_bypass` describe that
requesting tenant's local engine configuration. A missing tenant-specific entry
uses deployment defaults; this fallback is not an authorization decision.

Certificate-pinning failure counts, successful-handshake history and optional
automatic bypasses are also isolated by connection tenant. Candidate proposals
carry that tenant into review. Detection alone does not enable automatic bypass.
Host selection still needs separate verification against source/service/risk
conditions and the actual traffic path; it is not a full policy decision.

Use DNS hostnames, `*.example.com`, `*` or IPv4 literals in the explicit list,
without schemes, paths or ports. IPv6 literal patterns are not supported by the
current selector; use a DNS hostname for that destination. Unknown preset names
are rejected rather than silently removed. The remaining settings are preserved
when you change one field.

The server saves a candidate before adopting it in memory. If storage reports a
failure, the previous live posture remains active and the Console keeps the draft.
Restore storage, reload to check the current state, then retry. A lost or malformed
response can follow a successful save; it does not prove that nothing was saved.
An ambiguous storage commit or multiple independent writers requires separate
reconciliation. The server refuses empty, incomplete or invalid stored posture
snapshots during loading; restore or repair the authoritative snapshot rather than
silently replacing it with defaults. Missing snapshots still use initialization
settings. Preserve a backup before correcting older invalid data.

A control plane without an interception engine shows saved defaults and marks
live coverage unavailable. After saving, check configuration synchronization and
the serving Edge: a successful control-plane response does not establish fleet
convergence or actual DLP/tenant-restriction enforcement. Failed posture saves on
an Edge keep that bundle generation pending for retry.

In **Logs & Audit**, look for `admin_inspection_posture_changed` and the common
`admin_config_change` event. The dedicated event contains the actor, tenant,
deployment scope, requested mode, selection counts, a posture digest and
`saved`/`persistence_unconfirmed` outcome. It excludes destination lists. Input and
permission refusals appear in the common audit. These configuration records do not
replace traffic logs or confirmation that the audit storage itself is healthy.

## Authenticate on different traffic paths

On the inspected HTTP browser path, an authentication decision can redirect to
the tenant's portal. Non-browser HTTP clients receive the decision and, when
configured, an `X-Dsse-Stepup-Url` header. That HTTP header is for the client
application; it does not itself cause the endpoint agent to open a browser.

Steered native TCP uses a mux STEPUP frame and agent-mediated out-of-band sign-in.
See [East-West OOB behavior](east-west-policy.md#out-of-band-step-up) for the held
connection and retry behavior shared by this path. The federated gate's provider,
AMR, freshness, and scope limitations also apply to egress Authenticate rules.
Do not treat an eight-hour live grant as proof of a sign-in within the rule's
configured number of minutes.

## Diagnose a rule that appears ineffective

Check the customer, Active status, priority and broader policies first, then the
catalog identity/address/port resolution and **matches nothing** warning. Confirm
the serving Edge applied the configuration. Test a new connection rather than
assuming an already-established flow was re-authorized.

If the access decision is correct but content is not inspected, check host bypass
sources, the device profile, trust, and the protocol. If it is inspected but not
blocked, check the selected DLP policy, detector, match action, and visibility of
the actual payload. If public SSH unexpectedly follows East-West policy, inspect
destination locality and declared internal routes; port 22 alone does not make a
destination internal.

The authenticated `GET /admin/rules?plane=egress` API lists authored rules; the
Console also displays other effective contributions. A saved rule is configuration
evidence, and the application's allow/deny result plus logs is enforcement evidence.
Use [Verification](verification.md) to record them separately.

### Save failures and retries

With persistence configured, an authored rule is published and recompiled only
after its snapshot save succeeds. A failed create, edit, disable, or delete returns
an error and keeps the previous live rule set. Restore storage and reload the list
before retrying. A storage error can still follow an uncertain commit, so reconcile
the saved state before restarting the process. In-memory stores provide no restart
durability.

If the response is lost or incomplete, do not assume that nothing was saved. The
Console keeps the draft and its rule ID for a retry within the same editor. API
clients should also reuse the same ID after checking the current rule. A new draft
with another ID can create a duplicate. The Console refuses incomplete catalog
responses and requires the current customer context before submitting a change.

In **Logs & Audit**, the audit stream records `admin_authored_rule_changed` with
the actor, customer, rule ID, operation, result, and a digest of the rule. Rule names
and destination selectors are omitted. `saved` confirms the rule-store operation;
`persistence_unconfirmed` requires reconciliation. Neither result proves that a
remote Edge or an existing connection has adopted the change.

Implementation references: [rule model](../policyrule/policyrule.go),
[egress compilation](../policyrule/compile_egress.go),
[inspection selection](../policyrule/compile.go), [Console editor](../console/rules.js),
[effective egress view](../cmd/dsse-edge/effective_egress_admin.go), and
[HTTP enforcement](../cmd/dsse-edge/swg_http_egress.go).

For detector setup, action semantics, and file coverage, continue with [DLP](dlp.md).


### Changes to groups, services and destinations

Authored catalog writes are saved before the live catalog changes. If persistence
is not confirmed, the API returns HTTP 500 and retains the previous live entries,
aliases and generation. Restore storage, reload the list and retry. A transport
error or lost response can follow a completed save; inspect the list before
creating another entry. Enrolled-derived device entries have a separate inventory
lifecycle and are not covered by the authored catalog persistence guarantee.

Successful catalog API changes also rebuild the local compiled rules and TLS
inspection selectors. Changing a destination address or deleting a referenced
group no longer requires editing its rules to refresh that local projection. This
is not confirmation that every independent Edge has applied the change. Catalog
bundle reconciliation saves one complete candidate. If that save fails, dependent
authored rules are not applied and the same bundle generation remains retryable.
Catalog and rule storage are separate transactions; ambiguous commits, independent
writers and complete fleet consistency still require deployment validation.

Catalog mutations record `admin_asset_catalog_changed` with the accepted tenant,
actor, asset kind/ID, operation and result. Upserts include a digest of the submitted
or accepted record; names, addresses, members and storage errors are omitted. The
common HTTP audit remains separate. Neither audit proves remote delivery.

The Console’s **Policy decision check** destination preview evaluates TCP/443.
It is not a simulation of every protocol, port, identity, or existing connection.


### Candidate persistence and bypass registration

Candidate creation, observation, review and materialization publish their candidate state only after the configured store confirms the save. If saving fails, candidate write endpoints return HTTP 500 before their dependent rule creation or runtime apply step. Reload the candidate list, restore storage availability, and retry. Approval alone does not bypass traffic.

A manual bypass registration saves approval and materialization separately before writing its destination asset and Egress rule. These stores do not share an atomic transaction: an earlier confirmed step can remain after a later failure. Check both the candidate and its Egress rule, and the serving Edge's bypass state. A candidate status is not a receipt that every Edge has applied the bypass. The normal HTTP change audit records the request result; specialized candidate events describe candidate lifecycle and are not fleet enforcement evidence.

An unconfirmed save retains the previous live candidate snapshot and prevents replacing or detaching its writer until a later save is confirmed. It can still have changed persistent storage (for example, replacement completed but the final flush failed); do not treat an error as proof that storage is unchanged or crash recovery will select the old snapshot. Tenant erasure reports candidate-store failure as incomplete. Without a configured persister, candidates remain memory-only. Candidate observations that fail to save are not retained by the store; observation delivery is not a guaranteed audit stream.


A candidate with `status: materialized` records an adoption request. It is not proof of an active bypass: asset or rule saving can fail afterwards. Such failures return HTTP 500 with `partial: true`, the candidate ID/status and a `failed_stage` (`candidate_materialization`, `bypass_endpoint`, `bypass_rule` or `bypass_rule_removal`). Previously saved steps remain. Restore storage, reload, and repeat the operation. The direct cert-pin materialize endpoint accepts an already-materialized candidate for retry, but still requires the high-risk override when applicable and rejects a later rejected/suppressed candidate. Manual registration retains its stable candidate/rule IDs.

If rule removal is unconfirmed, the existing bypass may remain active. Inspect the Internet Access rule and retry removal; a rejected candidate alone does not prove the rule was removed. A configuration-pulling Edge refuses a candidate review that would remove an existing cert-pin rule: perform that authored change at the control plane. Within one HTTP server, candidate administrative writes are serialized to prevent a review from overtaking an in-progress registration. This does not coordinate other nodes, the general rule editor or background delivery.

Specialized bypass lifecycle audits identify the acting administrator and report `result: partial` with `failed_stage` when a later step fails. `candidate_saved`, `rule_operation` and `rule_state_confirmed` describe this operation's saved stages. `policy_materialized` indicates a confirmed bypass-rule write by this operation. `local_apply_requested` (also reflected in the legacy `runtime_hot_reload` field) means the local rebuild callback was invoked; it is not a fleet or traffic receipt. The common HTTP audit independently records the failed request. The Console labels candidate registration separately from the serving Edge's current bypass list and reloads both after adoption or a partial result.

### Restart and historical pinned-site candidates

Startup restores the saved authored rules; it does not regenerate a bypass from a `materialized` candidate. Deleting or disabling a cert-pin rule, or changing its inspection action, therefore remains effective after restart. A registration that saved its candidate or endpoint but failed to save its rule is not completed automatically by restarting. Candidate records remain visible in Sites to Bypass as history, but do not appear as additional active rules in Internet Access or as an inspection-policy source.

This also applies when upgrading older installations that retained only materialized candidates without authored rules. Such a candidate cannot distinguish a legacy bypass from a deliberate deletion or an incomplete registration. Review the current Internet Access rules and the serving Edge's bypass list. If a bypass is still required, explicitly register the host again through Sites to Bypass at the deployment's configuration authority. This uses the normal storage checks, audit and distribution path. Existing authored rules are preserved; no candidate history or endpoint is deleted by this change.


### Older SaaS Optimize selections

The current runtime takes SaaS bypasses from tenant-authored Egress rules. The legacy deployment-wide `inspection_posture.bypass_groups` field is retained for review; startup neither converts it into tenant rules nor clears it. It does not override a disabled, deleted or inspection-enabled rule, and it is not an additional active rule in Internet Access.

After updating an older installation, review Inspection Settings in each organization that needs a SaaS bypass. Use **Do not inspect it** to save that organization's rule, or edit the rule in Internet Access. Existing authored rules continue to apply. An older selection alone does not grant bypass. The deployment operator, outside a customer context and at the configuration authority, can use **Clear older selection** to remove the retained entry. This cleanup keeps authored rules unchanged; removing a service's current rule also leaves the older selection unchanged. Each action has its own saved outcome and audit.

The posture API accepts removal or retention of existing legacy selections, but rejects additions with HTTP 409. Use authored rules for new bypasses. A failed cleanup retains the previous live posture and returns HTTP 500; restore storage and retry. No automatic migration writes occur on restart. Upgrade all participating nodes before relying on this behavior: older binaries may still convert retained selections on their own startup. Clearing all obsolete selections at the authority and confirming configuration delivery removes that legacy input. These steps do not prove fleet propagation or actual traffic inspection; verify the serving Edge separately.
