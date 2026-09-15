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
Repair the catalog reference. A named service resolving to no ports currently
falls back to port 443 in the egress compiler; it is not equivalent to Any.

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

**Current authored inspection selection is destination-host based.** The bypass
compiler collects active bypass destinations into the engine's host set; it does
not apply the rule's source, service, risk condition, or access priority to that
selection. Do not promise a bypass only for one person or one source device because
the access rule names them. Inspect rules do not cancel a separately selected
host bypass merely by having a higher access priority. Review other device-profile,
static, and approved certificate-pinning exclusions as well.

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
