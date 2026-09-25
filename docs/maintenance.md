# Maintenance and 0.3.1 progress

Updated: 2026-09-25. Lantern DSSE is actively maintained by Lantern Networks, Inc.
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

These changes have been implemented and checked on the
[development PR](https://github.com/lantern-networks/dsse-core/pull/1).
They are **not included in the published 0.3.0 release**:

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

People directory readers now see Unknown instead of Normal when their risk
overlay read is denied or unavailable, and no risk edit selector is shown in
that state. A headed browser check against a local public-server synthetic
fixture confirmed the auditor view in English and Japanese; focused Console
regressions cover denied, failed, malformed and successful reads. This does not
confirm the administrator's display of user risk marks. The current public risk
read is scoped through enrolled devices and needs a separate tenant-safe user
risk path before that display can be accepted.

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
