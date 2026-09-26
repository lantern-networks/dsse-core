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

Upgrade note: the observation store reads legacy tenant maps as well as receipt-bearing
rows. Once reports are stored, the receipt-bearing format is written; rollback to
an older binary that cannot read it is not established by these checks.

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
