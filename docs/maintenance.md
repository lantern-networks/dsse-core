# Maintenance and 0.3.1 progress

Updated: 2026-09-27. Lantern DSSE is actively maintained by Lantern Networks, Inc.
The latest published version is [0.3.0 experimental](https://github.com/lantern-networks/dsse-core/releases/tag/v0.3.0-experimental), released on September 11.
**0.3.1 is in development and has not been released.**

The target is the week of September 28–October 4, 2026, subject to the release checks
below. This is a planning target, not an availability commitment. If it moves, this
page will record the remaining blockers and revised outlook.

## Log retention blocker

The standard ClickHouse deployment does not enforce Console retention overrides or
legal holds, and the PostgreSQL archive worker does not archive its rows. These
controls now report that limitation. New schemas preserve logs without automatic
expiry; existing volumes require the [schema correction](audit-and-data.md#clickhouse-retention-limitation-and-upgrade).
That correction prevents the old independent TTL deletion but does not implement
ClickHouse archival or hold-aware retention. Completing that data lifecycle and
checking storage capacity remain release work.

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
| Tenant erasure on receiving nodes | A failed tenant update or deletion defers only that tenant’s erasure; an unreadable registry still defers all erasure. Deferred tenants are named in sync errors, and the same generation is retried | Local stored-state, log and identity checks; signed HTTP polling through partial failure and recovery; regression checks for signature, live-tenant and enforcement-tenant protections. Deployed fleet erasure remains unverified |
| Tenant removal and settings distribution | Confirm deletion and purge-order storage before applying changes; retry received tenant changes after save failures before erasing local data; preserve confirmed edits between SQL-backed handlers | Authenticated deletion failure/retry and saved-state reload; signed same-generation retry after failed reconciliation; separate CP/Edge process checks for timezone, name, allowed-region changes and clearing, creation/deletion, session display and audits. Two SQL-backed handlers read completed edits from a dedicated local PostgreSQL instance. Simultaneous conflicting edits and deployed fleet erasure remain separate checks |
| Legacy SaaS header saves | Validate the whole header/switch request before writing; restore confirmed header files when a later save fails, and update the live resolver only after saving | Product HTTP failure/retry, fresh file reload and race tests; local browser input retention, retry/reload and actor/status audits. Failed restoration is explicitly reported; this is not a transaction across processes or crash boundaries |
| Download audit | Retain the issuing operator organization through link persistence and restoration; distinguish the issuer from an anonymous link bearer, and keep customer-issued links independent of the job creator | Authenticated HTTP issuance, restoration and consumption tests. This does not establish production audit delivery or change download authorization. Older versions may discard the optional issuer field when rewriting token data; mixed-version persistence is not covered |
| Tenant edits | Keep omitted settings and customer delegation withdrawal when changing tenant details; confirm tenant creation/edits before changing live state; record the authenticated administrator for self-service settings edits | Name-only, explicit-clear and protected delegation HTTP tests; failed-save state/generation preservation, retry and saved-state reload for create/edit; local operator browser edit, failed save, retry and reload with settings and actor audits preserved. Multi-CP session propagation remains a separate check |
| Legacy SaaS rule switches | Enable/disable and version rollback wait for a successful save; failed saves retain the live setting and do not record a successful version | Product HTTP failure/retry and fresh-store reload tests for switching and rollback; local browser failed save, retry and reload with saved data and actor/status audits; managed-provider behavior is separate |
| Incoming export compatibility | Reject activation of conditions the current Windows export cannot represent; refuse unsafe legacy exports while keeping disablement available | Authenticated registration/reactivation and saved-state checks, admin/device export checks, local browser refusal and corrected SMB save with audit comparison; Windows firewall execution remains unverified |
| Embedded evaluator configuration | Explicit false and empty tenant settings override a caller-supplied evaluator configuration | Regression tests with caller-supplied settings; the shipped executable does not populate these startup fields, so this is not a reproduced ordinary-operation defect |
| Incoming connection saves | Report storage failures for default changes and exception creation, edits and deletion; retain the current live setting until storage confirms the change | Four product HTTP failure/retry regressions and stored-state reload; local browser toggle failure/retry and audit comparison; shared-document regression preserving other settings. Windows application and real multi-region deployment remain separate checks. |
| Incoming connection exceptions | Preserve port, disabled state, approval/session limits and exact expiry during owner edits; show verified defaults and permission-appropriate controls; select explicit TCP ports | Local browser owner edit, reader reload and failed-read recovery; saved-state and audit comparison; editor and TCP export regression tests. Windows application and incoming persistence-failure handling remain separate release checks. |
| People | Retrieve the full directory for search; protect existing synchronized records during manual creation | Local browser operations, saved-state and audit comparisons, regression tests; PostgreSQL checked separately for creation protection |
| Directory updates | Preserve user-risk association after subject or email changes | Local browser risk changes, import and decision API checks, saved-state and audit comparisons; separate PostgreSQL regression |
| DLP and access rules | Preserve existing settings and references during ordinary edits; restore permitted read-only DLP listing | Local browser checks, saved-state and audit comparisons, automated regressions |
| Organizations | Preserve delegation choices and other stored fields during ordinary name edits | Local browser permission checks, saved-state and audit comparisons, automated regressions |
| Administrator onboarding and traffic overview | Check activation/login and period-based display of nonzero traffic data | Local browser and stored-data comparisons |

Local browser checks and separate database tests do not establish independent
control-plane/Edge operation, external identity-provider interoperability, or
long-duration reliability. Test counts are not a release-readiness percentage.

## Focused fixes in this tree

ClickHouse log exports report all matching records separately from the number
written to the file, so an export capped by its row limit is marked as truncated.
An interrupted database response fails the export instead of treating a partial
response as complete. Real ClickHouse checks covered capped and filtered exports
and tenant isolation; export-worker tests checked the resulting job status.
This does not complete ClickHouse archival or hold-aware retention.

Reapplying a carried node plan reuses valid existing certificates without requiring
the issuing CA private key. Invalid or mismatched material is rejected before the
node environment is rewritten. Installer verification reports skipped checks
separately from successful checks.

An explicit **Any destination** rule applies its HTTPS inspection choice while
preserving tenant and source-device scope. Before upgrading, review existing
Any-destination inspect and bypass rules: previously ineffective rules now apply.
In particular, an Any-source/Any-destination bypass rule disables HTTPS inspection
for its tenant. Local single-node checks covered real
HTTP allow/deny changes, HTTPS inspection/bypass changes, enable/disable/delete,
traffic after an Edge restart, and associated audit records. These checks do not
replace the multi-region and real OS acceptance below.

API-token creation and rotation preserve the one-time secret when a pending
response arrives after closing the form or navigating to another view, provided
the authenticated identity, tenant and connection remain unchanged. A changed
security context suppresses the secret and explains that the operation may have
completed, with instructions to check and revoke or rotate it. Closing or
reloading the browser page itself is not covered by this behavior.

Operator elevation requests awaiting approval show a pending message and do
not retry the original change. The distribution overview distinguishes unreadable
customers from confirmed empty release lists. Certificate inventory remains
readable when supporting status requests fail, while actions requiring that
missing information stay unavailable.

These Console changes have local browser checks using synthetic API responses
and regression coverage for the interactions described above. Deployed fleet
behavior, real OS installers, external integrations and the release checks below
remain outstanding.

Configuration receivers now leave a generation unacknowledged when saving People,
non-human identities, Sites, or device-CA changes fails. Polling retries the same
generation after storage recovers, including a CA update already applied in memory.

Revoking a delegated grant on an Edge now reports the revocation to the control
plane over the existing machine connection. Success requires the CP to confirm
storage and its audit record; other Edges receive the revoked grant through their
normal configuration polling. If confirmation is unavailable, the API returns 503
with `local_revoked: true` and `control_plane: "unconfirmed"`. Local denial remains
in effect. A node-local `-delegated-grant-store` file retains the revocation across
restart; memory-only storage cannot provide that guarantee. Pending reports retry
every 30 seconds. Upgrade the CP before Edges and configure the existing
`-audit-ingest-authority` Edge-to-tenant map (or the single-tenant CA binding).
The reporting endpoint only revokes grants already held by the CP; an absent grant,
unavailable CP, or missing machine identity remains unconfirmed rather than being
reported as a fleet-wide success.

PostgreSQL CI now includes all tests whose names contain `Postgres`, with the three
DSN variables used by the integration fixtures. This includes legacy user-risk
upgrade/restart tests and previously omitted shared-store tests. Local automated
HTTP, storage, restart, and configuration-polling checks cover these fixes;
deployed-fleet and GUI acceptance remain separate release checks.


Delegated-access grant creation and editing now wait for confirmed storage;
organization-scoped IDs prevent another organization's same-ID grant from being
overwritten. Shared-store reads and edits use the latest saved grants. Revocation
advances distribution generation and audits identify the administrator. A failed
revocation save returns an error and denies use on that process until a retry
confirms persistence; it is not a durable or fleet-wide revocation acknowledgment.
Receiving nodes also report save failures without acknowledging the bundle and
retain a local denial when saving a received revocation fails. Their
`-delegated-grant-store` must be a node-local file path or memory cache, not the CP
PostgreSQL authority. Empty/omitted grant bundles keep existing records.

Existing legacy grant snapshots remain readable. New snapshots use
organization-scoped keys; older binaries need a compatible pre-upgrade snapshot
for rollback. Store capacity limits simultaneously active admissions instead of evicting existing
grants or revocations. Revoked and expired history does not consume an active slot;
that history is retained to reject resurrection and can grow until tenant erasure.
An Edge receiving an authorized CP snapshot does not impose its own admission cap.
Stale active copies never revive locally revoked/expired grants. A section save
failure keeps the bundle unacknowledged, while independent later sections continue
to apply. Edits and revocations remain available at capacity.
Tests cover PostgreSQL peer registration/edit/revocation and saved-state reload,
HTTP permissions and audits, signed distribution, receiver save retry, and
revoked-access denial. Full Go tests, focused race checks and vet pass locally.
These are automated HTTP/storage checks, not new GUI or deployed-fleet acceptance.
This change awaits premerge review with its preceding dependencies.


Policy administration now distinguishes a saved server-side change from an
unconfirmed Network Extension snapshot. Create, delete and status-change audits
identify the administrator and distribution outcome; storage errors no longer
appear as invalid input or a missing policy. Status changes also invoke snapshot
publication. Lists and details refresh shared runtime state before returning it.
HTTP tests cover saved-state reload, failed publication and recovery, including
partially written files from the real local publisher. Two PostgreSQL-backed
handlers exercise edit, disable/re-enable, deletion and peer readback. Publication
success is not an acknowledgment from a running device; deployed acceptance remains
outstanding. This candidate also includes the policy persistence dependency from
PR82, which still requires premerge review.


Authored rule creation, editing and deletion now report unconfirmed storage without
exposing storage details, and record the administrator and outcome in domain audits.
Rule lists refresh shared rules and catalogs before returning them. Console edits
retain their draft after failure, reuse the draft ID on retry, verify save responses,
and refuse actions after an organization change. Edited cert-pin rules retain an
ordinary editable row when they no longer represent an unrestricted bypass.
HTTP persistence/compilation/audit checks, a two-handler PostgreSQL lifecycle, and
local Chromium create/edit/disable/enable/delete and failure/retry checks cover this
change. Browser APIs were synthetic; deployed fleet acceptance is still outstanding.


Delegated operators can cancel customer export jobs using the current customer
delegation; cancellation still refuses undelegated and unauthorized cross-tenant
requests. Export request, queue and worker lifecycle audits retain the operator's
principal and home-organization IDs. Cancellation identifies its own caller and
does not inherit the requester's operator identity. Product HTTP tests exercise
worker completion, opposite-role cancellations, spoofed metadata and delegation
revocation. A local browser cancellation matched the customer job and audit trail.

- SaaS tenant restriction saves distinguish unavailable storage (503) from invalid input (400), without returning storage details. Failed saves keep the previous setting; retry after recovery persists the edit. A local browser exercised failure and retry with audit checks. Separate CP/Edge process tests cover four providers through create, edit, disable and re-enable, signed polling and local HTTPS header capture. External provider sign-in and deployed TLS interception remain release checks.

Log exports now include the full selected local calendar days, including the
last nanosecond of the end date. The Console offers the supported NDJSON format,
rejects invalid or reversed dates without starting a job, and restores refresh
and download actions for completed exports. The API validates the request before
handing it to a worker. Local browser checks against product handlers confirmed
that a same-day export contains the start, midday and end-of-day records, excludes
adjacent days and another organization, and downloads a matching gzip file.
Creation and download audits were also checked. These checks use a local log store
and synthetic administrator session; shared-database and deployed-fleet acceptance
remain separate. Export details now show the latest server state, and queued or
running jobs can be cancelled from the Console. Local browser checks cover both
states; the running worker was held at the local reader boundary and released
after cancellation to confirm it leaves no partial download. Cancellation audits
identify the administrator who cancelled the job, separately from its requester.
Log outcome badges match complete status names, so revoked or incomplete records
are not presented as successful.

Disabled applications are now excluded from Connector selection, including an
explicit Connector ID, and from effective published routes. Re-enabling an
application restores its retained publication settings. Regression tests cover
ordinary name changes, disabling, re-enabling, withdrawal, republication and
deletion through a separate control-plane process and an Edge signed-config
poller, with administrative readback, file reload and audit checks. Local browser
checks cover disabling and re-enabling, saved settings and audit attribution;
the disabled application URL returns 404. An opt-in check using the built product
Connector in a separate process also verifies real localhost HTTP traffic after
publication, name edits, re-enabling and republication, and no backend requests
after disabling, withdrawal or deletion, with and without an explicit Connector
ID. The check uses local lab transport and a fixed Connector route allowlist;
it does not establish production certificate authentication, existing-session
termination, PostgreSQL or deployed-fleet acceptance.

DNS Filtering saves now publish the new live policy only after the configured
file save succeeds. A rejected save returns a retryable error and preserves the
previous policy. Explicitly removing the last DNS rule now reaches upgraded
Edges, so an obsolete block or redirect does not remain active. Boot-time and
legacy empty bundles retain the existing protection against losing local DNS.
The saved record adds `admin_authored`, and the signed bundle adds
`dns_policy_authoritative`; old records still load. Upgrade both the control
plane and Edges before relying on final-rule removal, then save the intended
policy again. Older Edges ignore the new marker. Local checks cover separate
CP/Edge processes, signed automatic distribution, actual localhost UDP DNS
answers, file reload, concurrent saves, and browser failure/retry/removal with
mutation audit records. These checks do not establish deployed-fleet acceptance.

Policy candidates now preserve the prior saved state when a change cannot be
written, and registration, review, adoption and discovery refresh return a storage
error instead of reporting success. If publishing an application succeeds but
approving its discovery candidate fails, the response and audit identify the
partial result. Store and product-HTTP regressions cover rejected saves, explicit
retry and fresh-store readback. A synthetic-session browser check covers manual
bypass registration failure, retry and reload; it does not establish deployed
traffic or independent control-plane/Edge acceptance.

Pinned-site adoption also checks destination and bypass-rule saves before reporting
success. A later failed save returns a partial result and does not request local
application; retry can complete the same registration without duplicate rules.
Failed bypass removal reports that the prior bypass may remain active. Candidate
history no longer appears as an effective rule or recreates deleted, disabled or
edited rules during startup. **Upgrade note:** a legacy materialized candidate
without a saved Egress rule no longer grants a bypass. Review the intended target
and explicitly register any still-required exception at the configuration authority.
HTTP, persistence, audit and repeated executable-startup checks cover these changes;
tenant-specific engine selection and deployed traffic remain separate checks.

Application creation, editing, publication, withdrawal and deletion now record
the authenticated administrator in their domain audits, including partial saves
and operator actions in another organization. Session credentials and directory
labels are excluded. Local HTTP regressions cover authenticated attribution and
partial outcomes. Local browser checks cover application edits, withdrawal and
deletion with saved-state and audit checks; this does not establish deployed-fleet
or remote audit delivery acceptance.

Connector Access rule and posture edits now validate the whole request and save
the four related settings together before publishing them. An invalid mode no
longer leaves a rule or TTL change behind; a rejected save returns a retryable
error and keeps the prior live configuration. Local product-HTTP checks cover
failure, explicit retry, administrative readback, file-store reload and
success/error audit records. A synthetic shared-store regression checks that
the edit retains unrelated settings already present in the persisted row. Existing browser
evidence is reused; this change adds no new GUI or deployed-fleet acceptance.

Connector Access configuration bundles now reject a snapshot if its policy
generation changes while the control plane assembles it. During an ordinary
partial/full posture edit, this could previously deliver an intermediate mode
under a generation that an Edge treated as current. A separate-process local
check covers rule creation, editing, removal and posture changes through the
signed automatic feed, Edge readback, control-plane file readback and mutation
audits. This adds no new browser acceptance or deployed fleet validation.

Groups & Services now keeps the previous live catalog and generation when a
group or service create, update, or delete cannot be saved. The Console receives
a retryable storage error without an internal path; a successful retry can be
read from a fresh store. Six focused persistence cases and product HTTP/audit
checks cover this boundary. This change has no new browser
acceptance for these six operations, and independent deployment propagation
remains a release check.

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

Older saved risk marks may have only a raw ID, with no reliable person/device or
tenant owner. During upgrade they stay active by raw ID across tenants; the
People page shows their count but does not assign them to a person. An operator
should upgrade Edges before relying on such a mark for person-risk enforcement:
an older Edge recognizes the raw ID only as a device ID, even while a newer
control plane sends the mark in a rolling upgrade. The operator must investigate
each mark before using the operator-only
`POST /admin/risk-signals/legacy-unattributed/resolve` endpoint to discard it.
That action requires the expected severity, an explicit discard confirmation,
and a reason, and writes an audit event. There is no atomic reassignment to a
typed person or device mark in this release. If a replacement typed mark is
needed, create and verify it before discarding the old mark; otherwise risk
enforcement may weaken during the transition. The U-1 compatibility change is
tracked in [PR #53](https://github.com/lantern-networks/dsse-core/pull/53)
and is not part of 0.3.0.

Devices readers whose risk overlay request is denied can still see the permitted
device list. The page shows a server-provided effective risk when present, says
Unknown when it is absent, and omits risk-edit actions. Other failed or malformed
risk reads require a retry instead of implying Normal. A local public-server
synthetic browser fixture checked the old and corrected English/Japanese views;
focused regressions cover the read boundary. This does not grant device write
permissions or establish independent CP/Edge propagation.

Recent focused fixes integrated into public main:

An isolated local two-process fixture now checks ordinary endpoint create, address
edit and final delete on a product control-plane HTTP handler. A signed automatic
feed carries each generation to the Edge; its admin read, durable asset file and
compiled egress deny destination follow the change. The control plane's three
asset-change audit records are checked. This is synthetic process/HTTP evidence,
not a new GUI acceptance or independently deployed CP/Edge traffic check.
The same fixture now checks Group membership and Service port create, edit and
final delete through the signed feed and Edge HTTP/durable-file readback. The
CP audit check covers all nine asset changes with tenant, actor, kind, ID,
operation and saved result. Deployed fleet communication remains unverified.

| Change | Checked behavior | Still to verify |
|---|---|---|
| [Tenant settings save retry](https://github.com/lantern-networks/dsse-core/pull/22) | After a lost save response, the editor retains the input, describes the result as unconfirmed, and permits a retry. A synthetic-browser check covered failure and retry. | Product-server persistence for that lost-response case and independent CP behavior. |
| [Application editing and publication](https://github.com/lantern-networks/dsse-core/pull/23) | A name-only edit retains existing routing and classification fields; closing a completed publication no longer submits it again. Regressions and a synthetic-browser check covered these paths. | Product-server saved-state and audit checks for this public change, plus independent CP/Edge traffic. |
| [Application rule-destination save result](https://github.com/lantern-networks/dsse-core/pull/24) | When a separate rule-destination save fails after an application change, publish, unpublish and delete now return a partial error with a partial audit instead of success. HTTP regressions checked all three, and a synthetic browser showed the publication warning and explicit retry. | The two stores are not atomic. Failed unpublish/delete retry is covered separately below; independent CP/Edge operation remains unchecked. |
| [Application destination retry](https://github.com/lantern-networks/dsse-core/pull/26) | A refused destination save keeps the previous in-memory endpoint so unpublish or delete can be retried. HTTP regressions reloaded both stores and checked the durable endpoint, partial and success audits; local catalog-snapshot tests cover adding and removing the destination on an Edge. Application-owned destinations cannot be changed through ordinary endpoint controls, and a synthetic browser shows where to manage them. | Cross-store atomicity, ambiguous shared-store responses, multi-CP convergence and independent deployed CP/Edge communication remain unchecked. |
| Shared application destinations | Concurrent control-plane writers now serialize updates to the shared asset catalogue, and fleet generation reads refresh from committed storage. Local shared-store and product HTTP tests cover non-erasing edits, refused saves, latest reads and bundle generation. | This is not cross-store atomicity or deployed CP/Edge acceptance. A separate-process PostgreSQL test is conditional on a test database; current public CI does not supply one. |
| Application destination name edits and distribution | Renaming a published application now updates the existing rule-destination alias while preserving its address, ID, ownership, tags and references. Focused product HTTP tests cover saved readback, refused saves and retry, ownership checks, audit and local CP-to-Edge bundle application. A separate-process local check exercises application destination changes through signed polling. | Existing browser evidence is reused, with no new GUI acceptance on this revision. Shared PostgreSQL, deployed CP/Edge traffic and cross-store atomicity remain release checks. |
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
| Asset catalogue audit and endpoint save errors | Endpoint, group and service writes now record a targeted audit with tenant, actor, asset ID, action and confirmed or unconfirmed outcome, without raw names, addresses or storage errors. A product HTTP check covered seven confirmed writes and three refused saves, including endpoint creation and deletion; endpoint save failures return 503 without exposing storage details or changing the live generation. | The HTTP and local outbox checks do not prove GUI acceptance, external audit delivery or independently deployed CP/Edge propagation. An error after storage writes can leave the storage outcome uncertain. |
| Asset-dependent rule refresh | Confirmed endpoint, group and service changes now recompile authored rules before the admin API reports success. A product-handler regression checked endpoint address and service-port edits, group membership edits and deletion, service and endpoint deletion, and that a refused save leaves the prior compiled rule active. | This checks one local product process and its in-memory effective policies. It is not a new GUI check or independent deployed CP/Edge traffic acceptance. |

Tenant inspection selections are now rebuilt as a complete snapshot. Updating,
disabling, re-enabling or deleting one tenant's HTTPS inspection exception no
longer replaces another tenant's exceptions. The runtime and administrative
readback use the same tenant selection, including after local or configuration-fed
Edge restarts. Device-scoped exceptions remain tied to their source device;
unresolved sources and services that do not include TCP/443 do not become
whole-tenant HTTPS exceptions. Pin-detection state and candidate attribution also
follow the connection's tenant.

Destination-only previews display a device-dependent result when necessary,
rather than claiming every device is inspected. Identity-only sources that the
TLS selector cannot evaluate are explained in rule listings. These checks cover
HTTP edits/readback, repeated executable startup, concurrent snapshot replacement
and isolated TLS handshakes. Browser checks use synthetic data and product rendering;
they do not establish deployed fleet traffic acceptance. Deployment-wide posture
controls and complete rule-priority/risk evaluation remain
separate work; this change does not claim those gates are complete.

## Observation delivery and candidate management (under review)

Edges report observed lateral flows and policy candidates to the control plane on
an independent delivery queue. The Console reads these inventories and sends
candidate edits to the control plane; a configuration-pulling Edge rejects those
edits instead of accepting a change that its next configuration update would replace.
Live TLS bypass status is still read from the Edge.

Counts and delivery receipts are saved together before acknowledging a report.
File-save failures, including a replacement whose final flush is unconfirmed, stay
unsuccessful on retry until persistence is confirmed. Shared-store reads refresh
before listing or adopting observations, so another control-plane process can see
received counts without restarting. Retries within the receipt window do not count
the same report twice; reports outside that window are refused explicitly.

Validation covers file-save recovery, concurrent shared updates, real PostgreSQL
report delivery and readback, request authority, Console transport tests and a
browser check with synthetic responses. This is not deployed fleet acceptance.
Delivery is bounded: at most 5,000 distinct observations are queued and another
5,000 can be in the current flush. New observations rejected at capacity are
counted in health data. Abrupt termination can lose unflushed observations, and
the downstream spool also has retention limits. The receiver refuses a known
standby; fencing a write across a leadership transition remains separate work.

Upgrade requirement: upgrade **all control-plane processes that share the observation
store together**, with report intake paused and every old writer stopped before any
new process writes the store. Back up the observation store before upgrading. The
new code reads legacy tenant maps, but the first saved report writes the v4 format
with receipt records. Old control planes cannot read this format and can overwrite
it, losing the inventory and receipts and counting retried reports twice. A rolling
upgrade with mixed old and new writers is not supported. After v4 is written, do
not restart an older binary against that store. Reverting requires stopping all
writers and restoring the pre-upgrade backup; observations received since the
backup are lost and pending Edge reports need operator reconciliation. This is not
a transparent rollback. Resume report intake only after every shared-store writer
runs the new version.

## Adopting observed flows (under review)

A batch that fails while creating destinations or rules now identifies the confirmed
rules, failed observation and remaining observations. Confirmed rules are compiled
even when a later item fails; retrying the batch skips already covered flows.
Repeated observation IDs in one request no longer create duplicate rules. Audit
records retain the administrator and partial/success result without exposing raw
storage diagnostics.

Coverage checks include the observed TCP port and refresh shared authored rules
and assets. A rule for one port does not mark another port as covered. Console
adoption stops when the latest observation cannot be read, uses the refreshed
record, and excludes UDP services from TCP port matching.

Checks cover file-save failures and recovery, repeated IDs, tenant boundaries,
read-only/pulling-Edge rejection, actual PostgreSQL peer readback, and Console
regressions. Browser checks use synthetic responses and inspect the arguments
passed to the rule editor; they do not cover its complete save flow or deployed
traffic. A batch is not a transaction across all rules and destinations. Review
partial results and current state before retrying after an unconfirmed save.

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

Upgrade compatibility: exceptions created by older Console versions may store a
catalog alias (for example WinRM-HTTP or PostgreSQL) as the service family. With
an empty or TCP protocol, these remain supported and export as TCP with the
saved port. UDP, approval/session conditions, or a port with neither family nor
protocol cannot be represented by the current Windows export. Disable or correct
such a record before enabling it; no automatic broadening of its rules is made.

Upgrade note: older API clients could store exception statuses other than `active` or `disabled` (for example `inactive`). Review and correct those records before upgrading; the current export rejects an unknown status instead of silently skipping it. Old Console-created records used the supported default status.


Pending route-distribution reconciliation: shared route edits preserve other CPs' committed decisions. Administrative reads and bundle publication refresh that shared state. A committed complete empty snapshot carries organization-wide route deletion to updated Edges; legacy omitted or empty sections retain their previous behavior. Receiver persistence failure prevents acknowledgment of the bundle so it can be retried. HTTP, real PostgreSQL peer CRUD, save-failure/retry and file-restart checks cover this change; deployed traffic and release acceptance remain pending. Older Edge versions do not understand the complete-empty marker, so all receivers must be updated before relying on organization-wide empty-set propagation. Leader-transition transaction fencing remains outside this change.

Pulling Edges use a node-local route cache even when another subsystem uses PostgreSQL. Configure `-connector-route-governance-store` with a per-node file path for restart persistence; an unset path uses an in-memory cache populated by the first pull. An explicit PostgreSQL route store is rejected for a pulling Edge to avoid writing received data back into CP authority. Control planes retain shared PostgreSQL route storage.


Pending DLP allowlist reconciliation: administrative writes require an explicit values array, confirm storage before changing live suppression, and preserve peers' committed tenant lists in shared PostgreSQL. Allowlist edits and clears now advance configuration generation and travel with signed DLP definitions. Updated receivers persist exceptions before applying them and retry failed saves at the same generation. Tenant-scoped readers receive only their own values; fleet readers retain the existing operator authorization requirement. Literal identifiers match exactly, numeric grouping and email case remain supported, and digits embedded in an unrelated identifier no longer authorize numeric findings.

DLP receiver libraries use node-local caches rather than CP authority even when another subsystem uses PostgreSQL. Explicit PostgreSQL library storage is rejected for pulling Edges; configure per-node files when restart persistence is required. Unset paths use memory. Older publishers omit allowlists and retain the receiver's previous list; explicit empty maps from updated publishers clear it. Older receivers ignore the new allowlist section, so update receiving Edges before relying on distributed exceptions. Invalid saved allowlist data now stops startup instead of silently starting with an empty list. Signed HTTP publication, receiver upload inspection, save/retry/restart, PostgreSQL peers and audit attribution are checked; deployed fleet traffic, remaining non-allowlist DLP shared-store reconciliation and release acceptance are still pending.

### DLP detector definitions and exact-match datasets

Custom classifier edits and dataset creation/replacement/deletion now confirm configured storage before changing the live scanner or returning success. Incomplete classifier replacements and empty or unscannable datasets are rejected without erasing existing definitions. An explicit empty classifier array clears classifiers; dataset deletion uses Delete. Organization-change guards reject stale edits.

Shared PostgreSQL updates preserve other organizations and datasets, and reads/config publication refresh the shared definitions. Received classifiers and datasets are saved before the Edge acknowledges their generation. Dataset snapshots retain the source salt so matching survives an Edge restart; source dataset values are not stored or returned by the administration API.

Validation covers administrative CRUD, peer reads with PostgreSQL, read-only permissions, audit attribution, signed publication and received scanning, failed-save retry, and startup/reload. No new deployed-fleet or GUI acceptance is claimed. These changes depend on the preceding allowlist/distribution work and require review before integration.

Compatibility: legacy dataset snapshots without a version continue to use the configured startup salt. Newly saved version-1 snapshots include the adopted salt; older binaries do not understand that salt contract, so rolling back a receiver with a different local salt is not supported without restoring its matching prior configuration. Invalid saved classifier or dataset snapshots stop startup with a generic error instead of silently dropping detection. Separate library files are not an atomic multi-file transaction; a failed update can leave partially written files, and must be retried before claiming completion. Policy-object persistence, leader-transition write fencing, and release deployment checks remain separate work.

### DLP policy save, peer reads and distribution

Named DLP policies now confirm configured storage for creation, editing, enable/disable and deletion before returning success. Rejected saves preserve the previous live policy. A completed file replacement whose final durability cannot be confirmed still returns an error; the replacement remains visible and pending a confirmed flush. Reload the saved state before retrying such an operation.

Shared PostgreSQL edits preserve policies from other CPs and organizations. Lists and bundle publication refresh policy state, and policy validation refreshes the referenced detector libraries. Received policy snapshots are saved before the Edge acknowledges the distribution update. Mutable metadata and identifier slices cannot change stored policy through a caller's copy.

Validation covers PostgreSQL peer CRUD and status changes, permission/organization guards, attributed audits, signed fetch and reference-only upload decisions, save failure/retry, restore and production startup. Inline fallback behavior for an unresolved/disabled policy reference is unchanged. Saved snapshots are validated as a whole; malformed data stops startup without rewriting it or logging its contents. Separate DLP library files are still not an atomic transaction. This change depends on the preceding detector-library work and requires premerge review; deployed-fleet and release checks remain outstanding.

### Inspection source compatibility

TLS inspection cannot resolve user/group/agent identity before decrypting a
connection. Inspect rules using these selectors, or an unresolved device source,
therefore apply to every source for that tenant and destination. Device-resolvable
inspect rules retain their device scope. Bypass rules never widen when a source
cannot be resolved. Review identity-scoped inspect rules before updating: they
may inspect additional users to preserve inspection instead of silently disabling
DLP under bypass-default.

### Named-service and save compatibility

When an egress deny or authentication rule references a missing/invalid service,
it now retains its authored source and destination restrictions across all ports,
until the service is repaired. Unresolved allow rules continue to match nothing.
This prevents deleting a named service from silently disabling an existing deny.

A confirmed non-atomic rule save counts as saved. If file replacement completed
but its final flush is unconfirmed, the rule store keeps the replacement live
and returns a storage error requiring reconciliation; it does not roll back only
the in-memory copy while leaving the new file on disk.

### Identity provider connection saves and distribution

Identity provider creation, editing, default selection and deletion now confirm configured storage before returning success. Rejected saves leave the prior live registry intact. Blank client-secret fields retain the latest saved secret, including when another CP performed the previous edit. Shared PostgreSQL mutations preserve other connections and organizations, and administrative reads and bundle publication refresh that state. Successful changes record the target organization and administrator without connection secrets or endpoints.

Receiving Edges save a complete registry before acknowledging the bundle; failed saves and incomplete snapshots remain retryable. Defaults and deletions survive reload. Pulling Edges use a node-local IdP cache even when another subsystem uses PostgreSQL: configure a per-node `-idp-connection-store` file for restart persistence. An unset path uses memory; explicit PostgreSQL storage for a pulling Edge is rejected to avoid writing received data into CP authority.

Validation covers PostgreSQL peer CRUD/default selection, authenticated permissions and audits, signed publication, blank-secret preservation, failed-save retry, reload and copy isolation. Existing complete JSON snapshots remain supported; incomplete or inconsistent saved registries are rejected at startup. A file replacement with unconfirmed final durability returns an error; reload before retrying because disk may already contain the replacement. This change requires premerge review. Interactive IdP login, deployed fleet and release acceptance remain outstanding; no new GUI acceptance is claimed.

### Inspection catalog persistence reconciliation

Catalog override changes and inspection posture edits now preserve the previous
live values when saving fails. Clearing an override and erasing an organization
report persistence failures instead of reporting success. Shared stores merge
updates against their current snapshot so one CP does not erase another CP's
changes; startup validates saved snapshots before replacing the live state.
Catalog feed application and rollback save their candidate before publication.

This change supplies storage primitives. CP startup wiring and administrative
refresh/context integration are tracked separately; it does not claim complete
fleet acceptance. An unconfirmed final flush is still reported as a failure;
operators must retry or reconcile storage before treating the edit as durable.

Older saved and signed inspection posture patterns remain readable during upgrades; newly edited administrative input uses strict validation. Retired catalog-feed signing keys no longer prevent startup: untrusted historical entries are excluded from rollback, and a current feed signed only by a retired key falls back to the built-in catalog with a warning. The original saved file is preserved for operator review. Previously valid signed payloads retain their original restore compatibility; new submissions still use strict validation.

Unchanged legacy host patterns do not block mode or known-bypass edits; newly added host patterns are validated. Rotate catalog signing keys under a new key ID. Reusing an existing key ID with different key material is rejected by saved-feed signature verification.

### Identity and enrollment storage reconciliation

Manual identity creation can reject an existing identity instead of overwriting
it. Identity registration and connector credential rotation return save failures
without publishing the rejected change. Non-human identities with the same ID
in different organizations are stored separately. Existing bare-ID snapshots
are read using each record's organization; new snapshots use organization/ID
keys. Back up this state before upgrading; do not let older writers rewrite the
new snapshot or assume a transparent binary rollback.

Enrollment inventory and token changes gain checked persistence and shared
transaction helpers. Seat allocation removal reports storage failure during
organization erasure. These storage changes precede the remaining administrative
route and CP startup integration; they do not claim complete GUI acceptance.

Seat-allocation storage must load successfully before startup completes. Missing first-boot storage remains valid, while malformed or empty existing files stop startup with a generic diagnostic and are preserved. Connector secret rotation accepts a confirmed in-place save and returns the new secret whose hash is stored; an unconfirmed save continues to fail.

### Access authorization and network boundary persistence

Grant and human-approval changes retain revocations during failed saves and
reject incompatible replayed authorization. Shared updates operate on the
current stored state, and checked erasure reports failures rather than removing
retry targets. Human-approval admission counts nonterminal, unexpired records;
revocation history remains present and cannot be replayed into an active grant.
Terminal history can grow until organization erasure and is not bounded by the
admission limit.

Steering exclusions and named-network boundaries save candidates before
publishing them and validate saved state. The organization erasure result
includes named-network persistence failures. Administrative context/startup
wiring remains a following migration unit. Back up authorization snapshots
before upgrading: new human-approval records use organization/ID keys, while
legacy bare-ID snapshots remain readable. Older writers must not overwrite the
new format; rollback requires a compatible backup.

Authorization request paths refresh shared grant and human-approval state at most once per five-second window; explicit administrative reads remain current. Grant-batch conflicts no longer prevent other correctly attributed revocations. Invalid legacy authorization rows are skipped with a generic warning during restore, preserving valid rows and the original file. VLAN and access-grant receive failures remain unacknowledged and retryable, and failed grant reports return an error. Human-approval lookups and revocations use organization-specific keys, including when two organizations use the same approval ID.

### Certificate and CA storage reconciliation

Internal CA changes validate a candidate before replacing current trust data.
Tenant CA registry operations retain other organizations and track incomplete
withdrawals for reconciliation instead of silently forgetting their targets.
Certificate/key replacement gains a private recovery journal; interrupted
updates restore a valid pair before reload.

The recovery journal contains private key material, is written with private
permissions, and must be protected with the certificate files and backups.
Only one process may own writable certificate files. A pending CA withdrawal
requires reconciliation before serving devices; it is not automatically
replayed against an unknown trust-store state. Administrative and startup
wiring using these primitives follows in a separate migration unit.

Existing CA files and signed snapshots may contain openssl preambles or public certificate chains. Restore keeps only the first public CA, matching the previous trust contract; new administrative inputs still require exactly one certificate. Unavailable authority stores publish an incomplete section, never an empty authoritative deletion. Invalid received CA snapshots remain unacknowledged so the next pull can retry. Failed administrative deletions return a storage error. Combined certificate/key PEM files remain readable at startup and reload; pair updates still require separate files.

### Legacy CA restoration compatibility
Saved and received legacy authority material restores its first public CA and discards accompanying text, chains and key material. New administrative submissions remain strict. Incomplete authority bundles keep the existing Edge trust without rejecting the remaining bundle. Startup also accepts a combined certificate/key file for reading; two-file updates still require distinct paths.
### Audit and search storage reconciliation

Audit log writes now record primary-write failures separately from downstream hook failures, including short writes. Health describes only the current writer process and does not promise durable recovery or downstream delivery. ClickHouse searches reject invalid row counts instead of returning a misleading empty result. PostgreSQL can count events without a region while retaining organization, stream, text and time filters. Streamed export storage can preserve a caller-supplied coverage comment in the gzip header. Administrative audit/export integration follows separately.

Package regression, race detection and the full Go suite cover these storage changes; this is not GUI or deployed-fleet acceptance.


Legacy CA normalization changes the in-memory and distributed public certificate only. The original database row remains until an administrator replaces it with a public CA certificate or deletes that authority in Console.
### Agent profile replacement and removal

The macOS installer checks that current and replacement profile organizations are readable and that required sidecars exist before moving configuration files. Replacing a profile for the same organization retains its device identity and, when no replacement token is supplied, its existing enrollment token. Windows profile removal also clears the issued-at display metadata. These changes preserve existing profile signature verification requirements.

Validation includes five isolated installer-adoption cases, shell syntax checks, host configstore tests and Windows test cross-compilation. Actual Windows registry execution and signed package installation are not claimed by these checks.
### Licensing and control-plane write authority
License application and feature entitlement edits now acknowledge confirmed storage, preserve the shared serial floor, and refuse writes from an expired leadership term. Startup restores license authority before starting leadership election; promotion refreshes the license before advertising leadership. DLP configuration writes stop when entitlement authority cannot be read.

Targeted startup, license, entitlement, cancellation and write-fencing regression tests cover these changes. GUI and multi-region deployment acceptance remain separate release checks.

An unreadable configured license or entitlement snapshot stops startup instead of silently starting with empty authority. A license serial that cannot be restored prevents every CP using that shared authority from advertising leadership; this affects leader-only management and audit intake. First distinguish storage connectivity failure from invalid stored data. If restoration is needed, use a verified authoritative snapshot at or above the last accepted license serial before retrying startup/promotion. Never reset the accepted serial to bypass this check. Write-term fencing here covers administrative blob UpdateContext calls; remaining background/runtime integrations follow separately.


### Administrator identity and authorization reconciliation
Administrator credential writes retain acknowledged state when persistence fails. Current stored roles and account status are checked for managed sessions; API token changes report save failures. Download bearers are consumed only after a confirmed shared write. Cross-organization writes retain explicit target checks, and failed authorization changes produce audit failures rather than success events.

Credential schema migrations 048, 049 and 051 carry TOTP replay counters, revision checks and writer protocol coordination. File and database regression tests are separate from Console GUI and deployed-fleet acceptance.


Administrator migration checks now include live shared authority, legacy principal IDs and credential-table purge after migration 051. See [administrator credential upgrade](admin-credential-upgrade.md) before changing a multi-control-plane deployment; all credential writers must move together.

### Retention, legal holds and tenant erasure

Retention and legal-hold edits now refresh shared state before saving and keep failed preservation requests effective locally. Pruning rechecks the saved policy inside the deletion transaction. Tenant erasure records a durable in-progress marker, checks protection between destructive steps, and retains its delivery markers after a partial failure. File erasure finishes its protection guard before reporting completion. Shared archival advances the chain and deletes exactly the archived hot rows in one SQL transaction; object-storage uncertainty stops further archival for reconciliation.

Only explicitly installed version 3 protection snapshots pause deletion after restart or leadership change for reconciliation. Default and version 2 deployments continue with their confirmed protection checks. Read [deletion safety recovery](deletion-safety-recovery.md), [tenant erasure recovery](tenant-erasure-recovery.md), and [archive recovery](archive-recovery.md) before enabling deletion on an upgraded deployment. Ordinary configuration editing remains available. This integration is not a deployment or release acceptance.

Retention migration review corrected two operational regressions before publication: normal restarts do not impose manual deletion permits (explicit v3 recovery policies retain their gate), and each transaction handles at most 1000 rows; a sweep repeats transactions for up to two minutes per stream. Old and new hold writers must be upgraded together; see the erasure recovery and archive preflight guides. Failed protective saves are unconfirmed and require reconciliation before restart.

### Console identity and account forms

People, device, identity-provider, access-approval, organization and enrollment screens retain the intended tenant and form state across asynchronous reads and failed writes. API token creation uses the server role catalog and its default role, sends the roles array, and shows only the returned one-time raw token. Profile and device-package forms validate the required deployment inputs before generating output. Existing risk warnings remain visible.

The Console regression suite and synthetic browser checks cover these form contracts; they do not establish acceptance of real identity providers, signed installers or deployed CP/Edge communication.

Device admission responses now include the authenticated tenant and the effective restore result required by the Console. Device risk reads use the control-plane route and validate its tenant; a denied risk permission still permits the inventory's explicit risk display. Manual person creation is create-only in both file and PostgreSQL directories, so a concurrent existing identity is not overwritten.

Device admission reads require the active CP when leader election is enabled; management routing to a standby returns a retryable conflict rather than a stale admission snapshot.

### Enrolment and inventory persistence

Device enrolment reports, enrolment-token issuance/revocation, inventory edits and seat allocations retain the accepted control-plane leadership term until durable storage completes. A storage or leadership failure is retryable and is not acknowledged as a saved enrolment. Promotion reloads shared inventory and seat allocations before serving writes; standby inventory refreshes cannot overwrite a promoted writer. Token issue/spend/revoke responses and audit records distinguish confirmed persistence from uncertain results.

Enrolment-report authorization now uses the Edge-to-tenant authority map as well as the verified client identity. Before upgrading a multi-tenant or operator-anchored Edge deployment, configure `-audit-ingest-authority` to cover each enrolling Edge and every tenant it serves. Missing mappings return 403 and keep reports queued; devices absent from CP inventory may lose admission on the next bundle refresh. Without a map, only a certificate resolved to the requested tenant is accepted. Startup warns when the CP report endpoint has no mapping; the warning cannot establish completeness of a configured map.

Inventory/seat reload failure prevents promotion; recover shared storage and restart an inventory process whose initial empty snapshot load failed. Route `/enroll` to the active CP. If token consumption commits but acknowledgement is lost, enrolment may require a new token after checking the existing device record; do not assume an uncertain response means the token was unused.
### Incoming exception edits and audit attribution

Partial incoming-exception updates preserve omitted restrictions and reject null or unknown fields. Storage failures keep the previous confirmed policy; successful changes and failures are attributed to the target tenant, including operator actions. Existing export checks continue to reject unsupported conditions instead of silently widening access.
### Cross-region revocation delivery

Pending revocation deliveries preserve peer changes in shared storage and resume after control-plane promotion. Peer acceptance and durable queue cleanup are reported separately; an old delivery acknowledgement cannot erase a newer request for the same identity. Snapshot loading rejects unreadable state instead of silently treating it as an empty queue. Existing outbox entries retain startup compatibility.

Revocation-mesh upgrades require all shared-outbox writers to move together; old writers replace the entire row and can lose peer updates. Existing file-backed queues still wait for election and resume on promotion. Peer URLs must be valid HTTP(S) base URLs without userinfo, query or fragment. An uncertain shared commit requires process recovery; retries for unreachable peers remain bounded and may need another promotion or restart.

File-backed mesh pending entries are resent only when the node holding that file becomes leader again. Unconfirmed enqueue intent can still be lost on a term change, and synchronous queue writes can delay session closure on a slow database; these are unresolved delivery limitations, not guaranteed atomic admission/outbox delivery.

### Device and user risk persistence

Risk edits report whether the requested state was applied and durably saved; failed protective saves remain visibly unconfirmed. Standby risk management does not serve stale authority, and promotion reloads shared device and user marks. Existing local snapshots retain their backend instead of being silently replaced by empty shared state. DLP-derived device risk records the actual application and persistence outcome separately from the original finding, and Edge synchronization retains marks on an unconfirmed empty feed. An authoritative CP feed still replaces the device map, including local DLP marks; separating those sources is not part of this integration.

Risk backend upgrades must explicitly reconcile every CP onto the same reviewed backend before enabling HA. Existing files are not implicitly imported; use the documented `-high-risk-store=postgres+import:` procedure with writers stopped. Existing empty/unreadable local paths (also for admission and policy stores) are retained for checked loading instead of silently selecting an empty shared backend; repair those paths or explicitly configure the intended backend before upgrade.

### Regional log searches and exports

Regional searches and export previews report whether the number of excluded records without region attribution is known. Downloaded regional exports carry the same limitation in gzip metadata; an unavailable count is never reported as zero. The count is a separate live query, not an export snapshot. Export jobs return detached metadata and check cancellation before the final object is committed, including small exports.

Export creation for an unknown stream now returns 404 consistently with searches. Cancellation can still race after final progress confirmation and before completion; this integration does not make object creation and job cancellation atomic.

Certificate administration now confirms shared saves before reporting success and retains the request leadership term through trust withdrawal. Startup recovers an interrupted certificate/key pair installation. Internal-CA updates invalidate outbound TLS transports using the certificate material itself; incomplete CA sections retain the previous trust configuration and are retried. Inspection-posture edits refresh the shared authority before changing controls and record results without destination lists. Manual key-health checks do not count as scheduled slow-signing intervals. These changes do not replace the release deployment and rotation acceptance checks.

PKI upgrade compatibility: CPs and standalone Edges without a remote certificate-history service can still replace certificates; configured history must confirm its save first. An unprovisioned optional internal-CA store omits its bundle section, preserving existing Edge trust without blocking other configuration. Explicit incomplete sections still require retry. Shared trust reads on standby CPs consume the signed committed revision; only the current leader authors revisions. Interrupted file-backed device-CA removals require [offline reconciliation](ca-withdrawal-recovery.md) before restarting. Certificate pair recovery and replacement use owner-only files; deployments sharing those files with a different process must provide an explicit controlled copy/access arrangement. Duplicate pre-change history entries are retained intentionally so the first replacement can be rolled back. Fleet-wide internal-CA listing requires a configured operator organization; tenant-scoped listing remains available.
AI service usage now verifies organization, requested period, coverage and totals before showing a report. Unavailable or inconsistent responses show Retry rather than zero usage; stale responses after a tenant or period change are ignored. Deploy the Console with its matching CP version: an older CP without the report tenant field is shown as unavailable, not as zero usage.

For the AI usage Console, API tokens need both `admin.ai.read` and `admin.tenant.read` so the displayed report can be verified against its organization. Standard administrative session roles already include both permissions.
### Steering exclusions and boundary administration

Steering exclusions now keep saved state on failed writes, attribute audit and version history to the target organization, and validate tenant/schema on CP feeds before replacing an Edge cache. VLAN edits preserve unrelated records and distinguish rejected input from unconfirmed storage; auditors remain read-only. East-west and SaaS restriction reads report unavailable shared storage instead of presenting stale authority. Candidate publication errors retain retryable storage failures. Update CP before Edges that require the validated exclusion feed.

Before updating an Edge that downloads steering exclusions, ensure its retrieval token belongs to the same tenant as its configuration bundle. An operator token or a token from another tenant now receives a tenant-mismatch response; the Edge retains its cached exclusions but cannot receive subsequent updates. Update the CP first, then update Edges after checking this token-to-tenant mapping.

### Connector management and organization-domain reconciliation

Connector secret replacement confirms persistence at both administrative URLs; errors do not return a usable new secret. Registration and heartbeat keep their audit/report follow-up when route discovery alone fails. Organization domain updates preserve concurrent changes, refresh shared state and retain the request leadership term. Connector lists reject malformed responses and avoid applying responses after the selected organization changes. These changes retain existing browser acceptance evidence for unchanged controls; real connector reconnection remains a deployment check.

Organization-domain storage must load successfully before startup. A malformed or unreadable configured file/database no longer falls back to volatile settings. Repair the configured store (valid empty form: `{"by_tenant":{}}`) rather than starting over existing data. Traffic classification uses the last applied domain snapshot while management reads report storage failures; shared peers refresh in the background.
### DLP library editing and findings

DLP identifiers, fingerprint sets and allowlisted samples keep editors open after an unconfirmed save and verify the returned saved values. Duplicate submissions and responses from a previous organization/view cannot replace the current list. Invalid list responses remain retryable errors instead of appearing as an empty library. Numeric identifiers ignore grouping and email values ignore case; other allowlist values match exactly. Findings retain the matching request context when loading details. Existing real-browser save/reload/audit evidence is reused for unchanged retained controls; this is not a new production traffic acceptance claim.

DLP library editors and findings require `admin.tenant.read` in addition to their DLP scopes when using API tokens. Console session roles already include this permission. An uncertain save (including a server or gateway failure) keeps the input but requires reloading the confirmed list before another edit. Allowlist reads and writes both use the control plane so an Edge's older delivered copy cannot overwrite a confirmed edit.


### Startup and received configuration reconciliation

Startup restores tenant and license authority before serving, and CP promotion refreshes and recompiles the latest authored settings before becoming available. A malformed existing tenant registry is an error requiring repair, rather than a fresh installation. Runtime settings received from the CP use node-local caches, and required-section failures keep the same configuration generation eligible for retry. This is not an atomic transaction across all sections: controls already applied stay in force while failed sections retry.

A receiving Edge must not also open the shared CP authority database. Before upgrading an Edge that combines `-postgres-dsn` with `-config-source-url` or `-config-source-endpoints`, keep shared authoring services on the CP, configure a local `-state-dir` for the Edge, remove its shared database option and any explicit PostgreSQL configuration-store overrides, and confirm that the CP contains the intended settings. Preserve old local snapshots for recovery and verify the first configuration pull before returning the node to service. The new binary rejects the incompatible combination before opening the database. Legacy SaaS bypass selections are retained for inspection but no longer recreate deleted rules at startup; author required bypass rules on the CP before upgrading.

Break-glass approval consumption is saved before session creation, so one approval cannot issue twice. A crash after reservation can consume an approval without delivering a session; an administrator must use a new approved request. Observation delivery follows CP endpoint changes and drains queued records to its configured spool on shutdown.


### Administrative screen reconciliation

Catalog group members resolve their returned IDs to endpoint names, service forms reject incomplete or out-of-range port rows, and managed application/certificate-pinning endpoints direct edits to their owning screens. DNS reachability includes inherited Site routes and reports unavailable information instead of an empty result.

Inspection, steering exclusions, internal CAs and predefined catalogs validate the returned organization and saved result, retain input after an unconfirmed write, and require a reload where the saved state is uncertain. PKI reads report unavailable required information, certificate history can be retried, and staging a replacement interception CA remains reachable after the first CA is installed. The screen distinguishes staging from promotion. Effective-policy previews use TCP/443 and saved authored rules, rather than treating historical approvals as active bypass rules.
