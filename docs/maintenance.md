# Maintenance and 0.3.1 progress

Updated: 2026-09-26. Lantern DSSE is actively maintained by Lantern Networks, Inc.
The latest published version is [0.3.0 experimental](https://github.com/lantern-networks/dsse-core/releases/tag/v0.3.0-experimental), released on September 11.
**0.3.1 is in development and has not been released.**

The target is the week of September 28–October 4, 2026, subject to the release checks
below. This is a planning target, not an availability commitment. If it moves, this
page will record the remaining blockers and revised outlook.

## What is being maintained

The current priority is reliability in everyday administration: creating, editing,
removing and enabling records; preserving saved settings; enforcing permissions;
propagating changes; and recording audit events. New features are outside the
0.3.1 stabilization scope.

The areas below have been checked in the
[development PR](https://github.com/lantern-networks/dsse-core/pull/1).
Some focused fixes have also reached public main, as noted below. None of these
changes is included in the published 0.3.0 release:

| Area | Change | Evidence available so far |
|---|---|---|
| People | Retrieve the full directory for search; protect existing synchronized records during manual creation | Local browser operations, saved-state and audit comparisons, regression tests; PostgreSQL checked separately for creation protection |
| Directory updates | Preserve user-risk association after subject or email changes | Local browser risk changes, import and decision API checks, saved-state and audit comparisons; separate PostgreSQL regression |
| DLP and access rules | Preserve existing settings and references during ordinary edits; restore permitted read-only DLP listing | Local browser checks, saved-state and audit comparisons, automated regressions |
| Organizations | Preserve delegation choices and other stored fields during ordinary name edits | Local browser permission checks, saved-state and audit comparisons, automated regressions |
| Administrator onboarding and traffic overview | Check activation/login and period-based display of nonzero traffic data | Local browser and stored-data comparisons |

Local browser checks and separate database tests do not establish independent
control-plane/Edge operation, external identity-provider interoperability, or
long-duration reliability. Test counts are not a release-readiness percentage.

## Focused fixes in this tree

DNS Filtering now rejects incomplete redirect and conditional-forwarding rows
before saving. Previously, clearing either required field and applying the form
silently removed that rule. Complete the row or use its Remove button to delete it.
Corrected saves, reloads, explicit removal, preserved settings and audit records
were checked in a local browser against the server and file store. Six focused
regressions cover the form behavior, and Console tests now run in CI.
This fix is not included in the published 0.3.0 release; independent
control-plane/Edge traffic and the release checks below remain outstanding.

Invitation message and link copying now waits for the clipboard operation before
showing success. If the browser refuses the copy, the handover dialog explains
how to select and copy the message manually. This affects both administrator and
operator invitations; it does not issue a new invitation or change its validity.
Four regressions check asynchronous success and rejection for both buttons, and
browser-enforced clipboard denial was checked with a synthetic invitation.
This fix is also not included in the published 0.3.0 release.

In Sites, connector routes now offer hostname and Named Network bindings in line
with the existing administration API. A subnet entered directly is retained with
guidance to define it on the Networks page; connector-reported routes are shown
as information without Adopt or Hold controls that the API rejects. Existing
configured bindings can still be removed. Local browser checks with a synthetic
connector covered add, reload, removal, stored routes and audit records against
the development server. The public server's rejection contract was checked
separately; public-server storage and audit were checked in the focused save
failure work below. Real connector traffic and independent control-plane/Edge propagation
remain release checks. This correction is not in the published 0.3.0 release.

If a connector's route list cannot be loaded, Sites now shows a Retry state
instead of an empty route list and hides binding controls until the read succeeds.
A synthetic-browser check covered a failed read followed by recovery without
a write; HTTP, transport and malformed-response regressions cover the same
boundary. Public-server persistence and audit are covered by the separate check
below.

For Sites and Connectors, adding or removing a network binding now reports a
storage failure instead of showing success for a change that cannot be saved.
The existing binding and in-memory generation stay intact, and an explicit
success or failure audit entry records the attempted action. Eight local
public-server regressions cover add and remove with file and shared-store write
failures, then a successful retry and reload. A synthetic browser session
confirmed the Sites failure, retry, reload and matching raw audit records using
the public server. Independent control-plane/Edge propagation and production
storage remain release checks. This fix is not in the published 0.3.0 release.

The file-backed Site catalogue now reports a storage failure for creation,
editing, deletion and enrollment-command rotation, without changing the live
record or its distribution generation. Previously these operations could report
success and appear in memory while the saved file remained unchanged. Eight
synthetic failure cases cover temporary writes and atomic replacement, including
saved-state reload and success/failure audit attribution. A separate local
control-plane and Edge process check covers ordinary Site creation, editing and
last-record deletion through signed bundle polling, administrative readback,
file reload and three control-plane mutation audits. Earlier browser evidence
for Site operations is reused; this check adds no new GUI acceptance. Deployed
fleet propagation, shared PostgreSQL and real connector traffic remain release
checks. This fix is not in the published 0.3.0 release.

Ordinary DLP Policy edits now keep existing settings that the editor does not
show, including disabled status, thresholds, metadata and additional device-risk
conditions. An identifier removed from the Sensitive Data library stays visible
as selected; the editor asks for an explicit deselection or restoration before
saving. Read-only users can still list policies when editor-only configuration
is unavailable. Twenty-eight focused Console regressions pass. A separate headed
browser check against a local public-server synthetic fixture edited a policy,
reloaded it, compared saved fields and the raw audit record, and confirmed that
an auditor can list but cannot edit it. Production persistence and real
control-plane/Edge traffic remain release checks. This fix is not in 0.3.0.

Internet Access rule edits now retain a saved DLP policy reference while the
policy list loads or is unavailable, including a reference to a deleted policy.
Selecting None explicitly removes it. Existing local browser evidence covers
editing, disable/enable, reload, saved state and audit against the development
server. A separate headed browser check against a local public-server synthetic
fixture confirmed that a deleted policy reference survives a name-only edit and
reload, that selecting None removes it, and that both saves match raw audit
records. Independent CP/Edge traffic remains a release check. This fix is not
in 0.3.0.

The admin audit now names mutations of `/admin/rules` as access-rule changes.
That endpoint serves both connector and Internet Access rules, so the former
connector-only label misclassified Internet Access edits. Focused English and
Japanese label regressions and a synthetic browser rendering check pass. This
display correction does not alter the saved rule or raw audit record.

People directory readers see Unknown instead of Normal when their risk read is
denied or unavailable, with no risk edit selector in that state. The public
server now saves and reads user risk separately from device risk, scoped by
tenant, and sends typed user marks to Edges ([PR #20](https://github.com/lantern-networks/dsse-core/pull/20)).
A headed browser check against a local synthetic fixture showed a saved High
mark, changed it to Critical, and showed Critical again after reloading the
People page; the saved file and audit record agreed. Focused tests cover tenant
and device ID collisions, permissions, save failures, legacy-state migration,
the CP-to-Edge HTTP feed, and tenant erasure. Independent deployed CP/Edge
traffic and multi-CP shared-state operation remain release checks.

Devices readers whose risk overlay request is denied can still see the permitted
device list. The page shows a server-provided effective risk when present, says
Unknown when it is absent, and omits risk-edit actions. Other failed or malformed
risk reads require a retry instead of implying Normal. A local public-server
synthetic browser fixture checked the old and corrected English/Japanese views;
focused regressions cover the read boundary. This does not grant device write
permissions or establish independent CP/Edge propagation.

Recent focused fixes integrated into public main:

| Change | Checked behavior | Still to verify |
|---|---|---|
| [Tenant settings save retry](https://github.com/lantern-networks/dsse-core/pull/22) | After a lost save response, the editor retains the input, describes the result as unconfirmed, and permits a retry. A synthetic-browser check covered failure and retry. | Product-server persistence for that lost-response case and independent CP behavior. |
| [Application editing and publication](https://github.com/lantern-networks/dsse-core/pull/23) | A name-only edit retains existing routing and classification fields; closing a completed publication no longer submits it again. Regressions and a synthetic-browser check covered these paths. | Product-server saved-state and audit checks for this public change, plus independent CP/Edge traffic. |
| [Application rule-destination save result](https://github.com/lantern-networks/dsse-core/pull/24) | When a separate rule-destination save fails after an application change, publish, unpublish and delete now return a partial error with a partial audit instead of success. HTTP regressions checked all three, and a synthetic browser showed the publication warning and explicit retry. | The two stores are not atomic. Failed unpublish/delete retry is covered separately below; independent CP/Edge operation remains unchecked. |
| [Application destination retry](https://github.com/lantern-networks/dsse-core/pull/26) | A refused destination save keeps the previous in-memory endpoint so unpublish or delete can be retried. HTTP regressions reloaded both stores and checked the durable endpoint, partial and success audits; local catalog-snapshot tests cover adding and removing the destination on an Edge. Application-owned destinations cannot be changed through ordinary endpoint controls, and a synthetic browser shows where to manage them. | Cross-store atomicity, ambiguous shared-store responses, multi-CP convergence and independent deployed CP/Edge communication remain unchecked. |
| [Networks read-only controls](https://github.com/lantern-networks/dsse-core/pull/28) | Administrators with only network read permission can view the catalog without Add or Delete controls. Focused Console tests, a product HTTP authorization check and a headed browser with synthetic sessions covered reader and editor views. | Independent deployed CP/Edge behavior remains a release check. |
| [Networks membership reads](https://github.com/lantern-networks/dsse-core/pull/30) | If a site's bindings cannot be read, the catalog shows Retry instead of claiming a network is unused or offering Delete. Focused regressions and a headed browser with a synthetic failed read and recovery covered the display; earlier local server checks covered ordinary binding saves and audit records. | The read and later Delete are not atomic, and independent deployed CP/Edge traffic remains unchecked. |
| [Sites network editing](https://github.com/lantern-networks/dsse-core/pull/31) | Failed bindings, catalog or connector reads block edits and offer Retry; an in-flight save blocks duplicate submissions and retains input on failure. Nine regressions and a headed browser on the public candidate covered a failed read and recovery without writes; earlier development-server checks covered saved state and audit. | Connector-route panels are a separate boundary. Independent deployed CP/Edge traffic remains unchecked. |
| [Site HA settings](https://github.com/lantern-networks/dsse-core/pull/32) | An ordinary Site edit retains its hidden routing namespace and HA policy. HA targets accept decimal non-negative whole numbers or blank; values such as `1.5` are rejected without saving. Focused regressions and a headed browser on the public candidate checked invalid input, a normal edit and reload; earlier local server evidence covered saved state and audit. | Product-server persistence for this exact public candidate and independent deployed CP/Edge behavior remain unchecked. |
| [Site save confirmation](https://github.com/lantern-networks/dsse-core/pull/33) | An empty or mismatched save response no longer reports success. The editor retains input and advises a reload because the write may already have applied; a matching acknowledgement and unique readback are needed for success. Focused regressions and a headed browser on the public candidate covered an applied write with an empty response, reload, and a normal confirmed save. | New product-server persistence and audit checks for this exact public candidate, plus independent deployed CP/Edge behavior, remain unchecked. |
| [Sites catalogue verification](https://github.com/lantern-networks/dsse-core/pull/34) | Failed or malformed Site and Connector reads now show Retry and keep management controls unavailable instead of implying an empty catalogue. Creation becomes available after a verified read, including a genuinely empty one. Focused regressions and a headed browser on the public candidate covered Connector 503, a mismatched row count and recovery without writes. | The two reads are not an atomic fleet snapshot. Product-server write and audit checks for this exact public candidate and independent deployed CP/Edge behavior remain unchecked. |
| [Connector availability display](https://github.com/lantern-networks/dsse-core/pull/35) | Sites now displays the server's Online or Offline connector answer instead of assigning fixed Active/Standby roles by connector ID. Focused regressions and a headed browser on the public candidate checked two online connectors and one offline connector before and after reversing their response order, without writes. | Availability does not prove a fixed routing role, real traffic or failover. Independent deployed CP/Edge behavior remains unchecked. |
| [Site deletion confirmation](https://github.com/lantern-networks/dsse-core/pull/36) | A Site deletion reports success only after a matching acknowledgement and a list readback showing the managed record gone. An uncertain response keeps the dialog open and blocks repeat deletion until the operator reloads. Focused regressions and a headed browser on the public candidate covered an applied deletion with an empty response, reload, and a normal confirmed deletion. | Product-server GUI persistence and audit were not newly checked on this public candidate. Server-side scope pinning and independent deployed CP/Edge behavior remain unchecked. |
| Connector rename and removal | File-backed management changes now wait for the registry save before returning success or recording a success audit. The Console verifies the exact acknowledgement and a fresh connector list before reporting success; an uncertain response asks for a reload and prevents immediate repeat writes. Focused Go and Console tests, plus a headed browser against a synthetic API, covered empty and valid responses for both operations. | An error after storage writes can leave disk state uncertain. Product-server GUI audit on this combined revision, live connector re-registration, and independent deployed CP/Edge behavior remain unchecked. |
| Network catalogue changes | Adding and deleting a Network now require a matching server response and a fresh catalogue read before the Console reports success. An empty response retains the form or confirmation dialog and prevents an immediate repeat write; a definite input error remains correctable. Console regressions and a headed browser covered empty and normal responses, while a local product-server browser check covered both normal writes, readback and audit details. | The readback is from the same local server and does not prove restart persistence or independent deployed CP/Edge propagation. |
| Network object storage errors | The product HTTP registration and deletion routes now return 503 if the object snapshot cannot be saved. Neither the live object catalogue nor its distribution generation advances on a refused save; after storage recovery the operation can be retried. Focused HTTP tests checked both routes, repeated failures, retries and a fresh Store reload; existing file-backed tests checked ordinary create and delete across fresh Stores. | A failed save can still leave the storage outcome uncertain. This change has not received a new product-browser check or independent deployed CP/Edge and audit-delivery acceptance. Bulk replacement and tenant erasure persistence remain separate work. |
| Network boundary-policy storage errors | Creating or editing a boundary policy now saves its candidate snapshot before publishing it. A refused save returns 503 without changing the live policy or distribution generation. A focused product HTTP regression reproduced the former 200 response, then checked failed create/edit, successful retry and a fresh Store reload. | The policy route is not an ordinary Console editor. No new browser, audit-delivery or independent deployed CP/Edge acceptance is claimed. A failed save can leave the storage outcome uncertain. |
| Network CP/Edge distribution | A local synthetic product-server check registered, edited and deleted the last Network through the control-plane HTTP API. A separately running Edge received each change through signed bundle polling; both product GET responses, fresh file-store reloads and three control-plane mutation audit entries agreed. | This checks two local processes and file persistence, not a deployed fleet, real traffic, shared PostgreSQL persistence or audit delivery. The earlier Console browser checks are reused; this check is not new GUI acceptance. |

## What still blocks 0.3.1

- Finish outstanding everyday-operation checks and fix reproduced defects with
  material effects on access, saved data or audit records. Reuse existing evidence
  while reconciling remaining checks and reviewing independent fixes for integration.
- Resolve or explicitly assess remaining persistence and restart limitations;
  postponing an investigation does not turn it into a passed check.
- Install from the public instructions and verify real allowed and denied traffic,
  control-plane/Edge propagation, regional failure, PKI rotation and sustained
  operation in the planned three-region, one-node-per-region deployment.
- Complete the applicable release checks, signed-artifact verification and
  release notes, including known limitations and upgrade guidance.

The latest release remains experimental. Merging a fix does not certify production
readiness or make an unreleased build a supported release.

## How changes reach users

We will integrate focused, independently reviewable fixes as they meet their own
review and verification requirements. A documentation change or a verified isolated
fix need not wait for every deployment test for the next release. The accumulated
development PR remains visible while its dependencies and integration path are
reviewed; it is not approval to merge the entire batch at once.

Each fix should describe the user-visible problem, the resulting behavior, relevant
checks and remaining limits. Related changes may be grouped when they must ship
together. The [contribution guide](../CONTRIBUTING.md#integration-and-release-checks)
explains the distinction between integration and release checks.

This page will be updated when a meaningful fix is integrated, the next blocker
changes, or the target week changes. Published versions and delivered fixes are
recorded in [Releases](https://github.com/lantern-networks/dsse-core/releases).
Report ordinary reproducible bugs through [Issues](https://github.com/lantern-networks/dsse-core/issues);
report vulnerabilities privately according to the [security policy](../SECURITY.md).
