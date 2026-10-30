# Acceptance and limitations

0.4.0 is an experimental release. This page separates what was measured on the
released server images and signed endpoint packages from earlier development
evaluation, lists the known issue, and lists the acceptance items that remain
open. An open item is a limitation of this release, not a passed check. Keep
source, package and deployment evidence distinct: a successful test of an earlier
build does not certify new bytes. The target topologies differ: one Region uses
three entrances to the same three Edges, while three Regions use an entrance for
each Region's own Edges. Grants and revocation span all six Edges.

## Measured on the released images and packages

A fresh three-Region installation was generated with the released installer and
the five released server images: three logical DSSE Regions in three availability
zones of one AWS Region, each with one CP+HAProxy host and two Edge hosts, plus an
independent identity-provider and application fixture. No S3 archive was
configured.

- Fleet verification passed 59 checks; 3 checks that the server installer cannot
  answer (client DNS, browser sign-in, fault behavior) were reported as not
  checked. PostgreSQL ran with three members in strict synchronous mode, etcd with
  three voters, and ClickHouse 26.8.36.3 on each control plane.
- No `dsse-edge` process on any of the nine hosts had a secret flag on its command
  line; each received its secrets through `-secret-env`.
- With the leader control plane's ClickHouse stopped, log search through the
  administrative entrance answered `503` with only `{"error":"log store
  unavailable"}`, and answered `200` again within seconds of ClickHouse restarting.
- With no organization setting, inspected HTTPS to a site that accepts only static
  RSA key exchange returned `200`, and the Edge recorded
  `TLS_RSA_WITH_AES_128_GCM_SHA256`. `GET /admin/upstream-tls` returned
  `browser_compatible` for both organizations.
- The signed and notarized macOS package was freshly installed. The Network
  Extension activated, traffic left through a Region A Edge, and a native request
  to a Connector-published internal application was held, completed Keycloak
  sign-in in the default browser, and resumed with HTTP `200` without a retry.
- On a Windows PC with about 970 firewall rules, the signed MSI installed (exit 0)
  and uninstalled (exit 0) without skipping cleanup or retrying. No product
  service, driver, process, DSSE WFP filter, firewall rule or installation
  directory remained.
- The signed MSI was then freshly installed for the deployment. Strict HTTPS
  over IPv4 left through a Region A Edge and strict HTTPS over IPv6 succeeded. A
  native request to a Connector-published internal application was held,
  completed Keycloak sign-in in Chrome, and resumed with HTTP `200` without a
  retry. An SSH session to a management host excluded by the signed profile
  connected after capture started.

- `govulncheck` on the release source reports no vulnerability reachable from
  DSSE code. Two advisories, GO-2026-6866 and GO-2026-6860, affect
  `golang.org/x/net/html` in the required `golang.org/x/net` v0.61.0; no DSSE
  binary imports that package. GO-2026-5932 concerns the unmaintained
  `golang.org/x/crypto/openpgp` package, which has no fix and is not imported.
  The next release updates `golang.org/x/net` to v0.62.0, which fixes the two
  `html` advisories.

## Verified development scope

The one-region, three-combined-node evaluation completed 24 verified TLS/HTTP
connections through each entrance, 72 total, with all three Edge backends observed
at every entrance. This is not a capacity guarantee or complete per-flow attribution.

Development evaluation exercised three logical DSSE Regions across three availability
zones in one AWS geographic Region: one CP/L4 node and two dedicated Edges per Region,
plus an independent identity-provider/application fixture. This is not evidence of
operation across three geographic AWS Regions or Internet inter-region latency.

The evaluation included real Mac and Windows agents, IPv4/IPv6 and allowed/denied
internal traffic; real default-browser Keycloak authentication and Mac Passkeys;
grant reuse and revocation across six Edges; fresh verification after revocation;
regional entrance/service loss; CP/state-primary loss and authentication through a
replacement authority; and concurrent held connections reaching both Edges per Region.
Shared-origin Edge restart and pending-callback recovery were also evaluated in the
smaller one-region multi-Edge topology.

Some earlier fault trials failed and led to fixes. Final blackholed-entrance recovery
had roughly 26 seconds between the first failed sample and the first successful sample;
the fault-start-to-stable-success measurement on Mac was about 33 seconds. Other
regional trials had roughly 20–30 seconds of failed Mac samples and 0–20 on Windows.
Sampling was generally every five seconds. These are measured cases, not a universal
30-second SLA. Existing TCP streams are not transparently migrated. A grant-revocation
trial took about seven seconds to observe all six Edges refusing the old grant; an API
acknowledgment is not proof of simultaneous application everywhere.

## Known issue: the audit hot store is not replicated between control planes

Each control plane runs its own ClickHouse hot store, and the stores do not
replicate to each other. Audit records are written to the ClickHouse of the
control plane that holds leadership when they are ingested. Log search, export
and manual hot-log deletion read only the current leader's ClickHouse.

As a result, after leadership moves to another control plane:

- Search and export do not return records that were written while the previous
  leader held leadership. Those records remain on the previous leader's disk.
- A manual deletion preview does not count those records, and a completed
  deletion job does not remove them. A completed job is not proof that no copy
  of the selected records remains.
- If that control plane's disk is lost, the records written while it was leader
  are lost. Without an external S3 archive, the hot store holds the only copy.

Leadership changes when the leader control plane stops, restarts or loses its
database lock, so this applies after maintenance as well as after failures.
A later release will replicate the hot store across control planes.

## Open acceptance items

These items were not completed for this release. Treat each as a limitation when
deciding where to deploy 0.4.0.

| Item | Evidence still required |
|---|---|
| Tenant isolation | Regression coverage of deployment-only distribution APIs and tenant APIs; upgrades and data migration from any existing 0.3.1 installation require separate acceptance |
| Audit storage | Accept local-only mode with durable hot-store capacity, backup and restore evidence. Verify scoped, audited manual hot-log deletion with preview, legal-hold refusal and confirmed completion on PostgreSQL and ClickHouse. If external S3 is selected, verify CP-scoped credentials, real Put/Get, outage retention and replay, and an operator-visible failure/backlog/recovery alert through the signed webhook and Console; S3 itself is not a prerequisite for local-only installation |
| Final image installation | After both supported plans select the final scanned digests for all five built image roles, freshly generate the one-Region and three-Region installations on real Linux hosts. Verify three-member synchronous PostgreSQL replication, primary failover and rejoin, etcd quorum, ClickHouse, CP startup without S3, and backup/restore using the final images. Earlier MinIO-era AWS trials and two-member local HA tests do not satisfy this gate |
| Dependency security | Current blocking source/binary checks for shipped components, including the S3 client library, plus the [image inventory and per-image scanner](../../../scripts/scan_release_images.py) for shipped third-party bases and built images selected by both plans. The scanner also requires a CycloneDX inventory for each built image and rejects unresolved local Go module identities such as `pkg:golang/..`. No missing digest, image role, component identity or high/critical finding may be reported as approved |
| macOS package | Exact PKG hash, Developer ID signatures, accepted notarization/staple, fresh installation, steering and normal-network recovery |
| Windows package | Exact MSI/payload hashes, EV signatures/timestamps, Microsoft driver validation, fresh installation, updater publisher argument validation and WFP recovery |
| Generic packaging | No baked tenant/deployment inputs; same signed package verified with separately supplied independent deployment inputs |
| Admin Console | With the final Console and server images on a real deployment, review every tenant-administrator and operator page against actual API responses, including populated and empty states, API failure and session expiry. Verify device identity, OS, last report and certificate details against enrolled endpoints; exercise create/save/read-back/cancel/delete only in a dedicated test tenant and confirm cross-tenant and role restrictions. Local synthetic-data screenshots and navigation checks do not satisfy this gate |
| Authority failure | Full Connector/held-flow test with a slow synchronous database replica; distinguish database write delay from an unreachable Region |
| Authorization availability | Local regressions now distinguish an unavailable/stale shared grant store from a verified empty result and suppress new login ceremonies when grant authority cannot be verified. Repeat this with the final binaries and an actual shared-store outage across browser and native traffic before approval |
| Grant distribution and shared-store scale | Edge-to-CP reconciliation splits reports within the receiver's 256 KiB request limit and retries the whole set after a failed batch. For current Edges, a signed config-bundle reference fetches signed grant pages; the Edge verifies every page and does not acknowledge the generation after an incomplete, changed, or untrusted snapshot. The CP reuses a sorted grant view within one generation. PostgreSQL migration 056 stamps both grant blob keys, including writes by released CPs; unchanged pages probe those revisions without fetching, decoding, or hashing the complete snapshot. After confirming shared authority, an identical Edge grant report skips its write transaction; changed, pending-denial, or uncertain reports retain the transactional merge. Revision rollback, missing keys after initialization, and authority errors fail closed. Older schemas retain full reads. Older Edges retain inline grants for compatibility. Changed reads and writes still use shared-store whole snapshots, with write contention and Edge memory growth remaining. Measure large-grant new-Edge join and revocation with final binaries, replace whole-snapshot writes with row or delta access, and remeasure before making a large-fleet claim |

Manual deletion now has a durable CP job journal, scoped preview and confirmation routes, Console controls, local PostgreSQL receipt tests and ClickHouse frozen-predicate mutation tests, including CP promotion and late-arriving rows. It still needs a final-image installation and authenticated end-to-end acceptance before this gate can pass. Archive health has shared CP status and durable outbox handoff. A generated publisher delivered a signed alert over verified HTTPS in an isolated Linux/PostgreSQL test, but outage notification and recovery have not passed real-S3 acceptance. Neither item is a completed release gate.

The local-only audit-store smoke test now uses the installer's pinned ClickHouse
image and actual first-boot schema. It inserted synthetic rows for two tenants,
stopped the store, copied its data volume, restored that copy into an isolated
volume, verified both rows and the materialized rollup, then wrote a new row.
Run `scripts/verify_local_audit_restore.sh REPORT_DIR` to reproduce it. The test
does not restore PostgreSQL control-plane state, issuer keys, configuration, Edge
spools or an active multi-node fleet. Production backup and full recovery therefore
remain part of the audit-storage and deployment acceptance gates.

Large shared-grant snapshots and concurrent writes can cause multi-second authorization
outages. The current architecture is not certified for large multi-tenant production
fleets. A successful small deployment is not a substitute for that acceptance.
The local grant-authority regression checks signed evidence, an empty signed result,
invalid or unavailable snapshots, and shared-store read failure. They do not prove
end-to-end behavior during a real database or CP outage; that remains a release gate.
HAProxy's resource-derived startup memory budget is not a reservation: inspect actual
capacity after startup/restart and account for other workloads consuming memory.

Direct Google Workspace, Okta and Entra ID acceptance, identity-bound SMB attribution,
all platform/assurance combinations, production capacity and geographically separated
failure domains remain separate acceptance items. The earlier 16-hour 0.3.1 observation
does not establish 0.4.0 endurance. Read [current implementation limits](../../release-overview.md)
as well; no existing security limitation is waived by these tests.

## Regional ingress and upgrade acceptance

Local regressions cover approved transport SNI validation and selection of the
processing Edge's regional Portal for new three-Region ceremonies, production
mux resumption, interception identity retention,
unknown-ingress rejection, unchanged three-origin upgrade configuration,
activation gating and explicit tenant Region-impact confirmation. These are code
checks, not a real entrance outage or live rolling-replacement measurement.
Before release, stop only an entrance/CP-L4 host with its Edges
still healthy and run repeated fresh authentication on both supported endpoint
OSes through every surviving entrance. Also measure one-node-at-a-time upgrades
with fresh authenticated native traffic throughout the activation sequence.
