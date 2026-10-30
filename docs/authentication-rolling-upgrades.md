# Authentication state during rolling upgrades

## Fresh declared shared-fleet installations

After the full plan's members are started and database synchronization is ready,
run `dsse-install -activate-auth -dir /opt/dsse -admin-token-file
/opt/dsse/authority/operator-api-token` on the issuer. The private token file is
created by `-bootstrap-admin -admin-token-file ...`, never copied into carries.
The helper uses the existing authority API, retains all currently enabled
features, waits for fresh authenticated reports from every active census member,
and verifies the committed generation, manifest and feature set at every planned
Edge's protected admin route. `phase: ready` and exit 0 are required. A timeout
lists unready members; fix the cause and rerun the same command. It does not
replace or retire a member, change a census, bypass TLS, or admit an Edge subset.

Edge inspection uses the issuer-only `authority/installation-state-read-token`
created by bootstrap, with exactly `admin.state.read`; the operator token stays
on the CP side of this setup command. Use authenticated
`GET /admin/config-sync-status` to monitor `auth_rollout` during updates;
anonymous `/healthz` does not expose that state. After setup and monitoring no
longer need the dedicated reader, a named administrator may revoke it at the CP.
See the [installation guide](releases/0.4.0/install-multi-edge.md) for replacement
credentials and later setup checks.

Default activation includes evidence, single-request grants, ceremony recovery
and revocation reauthentication. Device/user binding remains an explicit opt-in:
prepare the endpoint versions and administrator assignments described in
[device-user authentication](device-user-authentication.md), then rerun with
`-auth-features device-user-session-v1`. This is not an automatic migration of a
released deployment. Existing fleets follow the staged procedure below; do not
add a shared-origin map before that procedure permits it.


This describes the compatibility mechanism under development. It does not certify
an end-to-end rolling upgrade of packaged CP/Edge deployments or OS agents.

## Storage and feature boundaries

The shared PostgreSQL `grants` record remains the released 0.3.1 ID-to-grant map.
New evidence, including `auth_time` (absent from the released 0.3.1 JSON contract),
is retained in `grants_evidence_v1` in the same transaction. A node upgraded from
a released local cache may restore missing issuer/configuration/auth-time evidence
only from a signature-verified CP bundle whose legacy authorization fields match
exactly. Ordinary peer grant reports cannot enrich that evidence. Existing evidence,
identity, scope, assurance, lifetime and revocation cannot be replaced. Ordinary
grant revocation is visible to both implementations. Single-request grants and
future rows with required features appear only in the modern sidecar and the
protected part of signed configuration bundles. An old reader must never treat a
single-request grant as a reusable grant.

A deployment-wide census, `auth_rollout_v1`, records every expected CP and Edge
process, including offline members. Recent reporters do not define membership.
Each member has its own certificate fingerprint, role, installed-version baseline
and stable ID. A retirement must name the member and give a reason; deleting a
member from a new census is rejected. A generation compare-and-swap protects
operator changes. The baseline IdP configuration digests are immutable during
migration; changing an IdP invalidates legacy grant acceptance.

## Node evidence and completion

Every complete installer plan, including unprofiled three-region/one-machine-per-region
and single-machine plans, produces `auth-rollout-census.json` and individual CP/Edge
client certificates. A fresh no-plan `-host` install creates a census for its local
CP and Edge pair; both must report before activation. Existing installations without
a census require a complete `-plan` inventory, rather than guessing that the local
machine is the entire fleet. A deployment
carry includes only the destination's process keys. The issuing directory retains
the other keys under `authority/`; it must not be copied to joining machines.
Planned nodes initially say `awaiting-first-report`, not an invented running version.

Processes send an mTLS `POST /fleet-capabilities/report` every 15 seconds. The CP
matches the verified peer certificate to the expected member, checks the deployment
generation, and records its own receipt time. A claimed node name or bearer token
alone is insufficient. The reporting client follows the existing CP data-plane
leader selection and does not follow HTTP redirects. Standby CPs also report
through the authority's endpoint.

The CP activates `grant-evidence-v1` and `single-request-v1` only after **every
nonretired expected member** reports support within the preceding two minutes.
Missing/offline nodes prevent completion. The completion latch and enabled
capabilities survive CP promotion and process restart. A stale census cannot
bootstrap over existing state, and a later report cannot downgrade enabled
capabilities.

Edges receive the state inside the existing signed configuration bundle. The
persisted Edge cache rejects unsigned state, older generations/revisions, and a
return from complete to mixed. For mixed-version compatibility, a new state revision
starts a receiver-local, monotonic lease lasting at most two minutes. CP timestamps
specify its duration, not the Edge clock deadline. Replaying a revision cannot renew
the lease; restarting an Edge clears its mixed lease until a newer revision arrives.
Reports advance the mixed-state revision, but do not advance the configuration
generation. Edges receive rollout state on every signed poll, including polls without
configuration changes.

An invalid or unavailable rollout section retains the prior state and does not block
policy changes, revocations or IdP settings. The Edge configuration-sync status exposes
`auth_rollout.status` (`accepted`, `rejected`, or `omitted`) with last attempt/acceptance
times; acceptance is not proof that a mixed lease was renewed. A CP distribution read
failure is logged and omits the section.

Completed capabilities are durable and do not require an unexpired mixed lease, so
a CP outage does not disable them. Identical completed reports whose advertised
capabilities are all active, and identical activation requests, do not rewrite the
authority record. Reports advertising a still-inactive capability retain fresh
receipt times so that an operator can activate it later. These reports do not serve as a liveness
monitor after completion. An absent section from an old CP cannot reset completion.
The local process must
also be a nonretired member of the census with the expected identity.

## Authorization behavior

- During a confirmed mixed deployment, a legacy grant without issuer/configuration
  evidence may satisfy an ordinary rule until its original expiry. Tenant, device,
  IdP, scope, assurance, age and revocation checks still apply. The captured IdP
  configuration must match. Every expected member must have a known installed
  version or an authenticated capability report.
- An uninitialized census, unknown installed version or expired distribution lease
  does not enable legacy acceptance.
- After completion, grants without issuer/configuration evidence are rejected.
  Existing grants with valid evidence continue to work through restarts.
- A single-request (`max_age=0`) ceremony and release require fleet capability
  activation. A rollout change between start and callback is checked again.
- Draining rejects new ceremonies; existing issued grants remain usable. An
  in-progress ceremony or held native socket is not recoverable across destruction
  of its owning process by this mechanism.
- Authorization store reads currently cache shared data for up to five seconds.
  Cross-process revocation is therefore bounded by that refresh period, not claimed
  to be instantaneous. This does not describe termination of already-open streams.

## Existing 0.3.1 deployment migration prerequisites

Do not treat the new-install census as proof of old nodes' installed versions.
The old binary has no capability reporter. Before the first upgraded authority
initializes its census, the operator must inventory **all** installed CP/Edge
versions, retain evidence, and populate the baseline versions in the census.
Do not replace an unavailable node with an assumed version or silently retire it.
Do not clone a no-plan standalone directory to add a region: use a complete plan
and an explicit membership migration with individual identities. The `-region`
shortcut rejects a directory with a census. Existing multi-node installations must
use their complete plan when repairing generated files.

Individual identities must be provisioned from the original issuing directory,
and existing IdP configuration must be readable when the initial baseline is saved.

The upgraded authority must serve the capability endpoint and signed distribution
before an upgraded Edge relies on legacy compatibility. Preserve database quorum
and the normal drain/leader-transfer procedures throughout the upgrade. Do not
revert to an old-only authority after relying on leased rollout state.

Deployment-operator API methods are:

- `GET /admin/auth-rollout`: inspect the committed census and reports.
- `PUT /admin/auth-rollout`: submit `previous_generation` and the complete next
  `manifest`; this requires `admin.platform.write`.
- `POST /admin/auth-rollout/activate`: explicitly request the current `generation`
  and `features`; the same complete-census/fresh-report checks apply.

A new manifest generation also requires distributing the matching census to the
reporters. Existing identities cannot silently change or disappear. Membership
expansion, certificate renewal and downgrade procedures require an explicit
operational migration; this document is not an automated upgrade command.

**After completion, rolling a single CP or Edge back to the released 0.3.1 binary
is unsupported and prohibited.** It would issue evidence-free grants that modern
nodes reject, causing repeated authentication. Retain compatible binaries; a full
rollback requires a separately planned, consistent fleet/state recovery, not an
individual-node downgrade or reopening the completion latch.

## Verification and remaining acceptance work

Local regression tests cover individual mTLS reports for three CPs and six Edges,
missing/stale/wrong-member reports, signed cache restart and downgrade rejection,
transactional concurrent CP updates, old-writer `auth_time` preservation through
storage/bundle/report routes, clock skew, isolated rollout failures, stable policy
generations, and named/unprofiled/single-machine installer inventories and carries.

A disposable PostgreSQL test runs three separate native-mux test processes. It
uses the frozen released grantstore/gate and current gate, drains and restarts each
process, checks continued native data on existing streams and other nodes, reuses
legacy grants in the mixed phase, rejects them after completion, and checks
revocation of evidence-backed grants. This harness uses the current mux transport;
it is not a claim that the released packaged executable or OS clients were tested.

An opt-in executable integration test, `TestAuthReleasedAndCurrentExecutables`,
launches three CPs and six Edges using separately built released-0.3.1 and current
`dsse-edge` executables, an empty disposable PostgreSQL database, loopback TLS
listeners and a test L4 authority entrance. It exercises actual CP advisory-lock
promotion, signed config polling, individual member mTLS reports, native-mux
forwarding and authentication challenges, released whole-map writes, one-at-a-time
CP/Edge replacement, mixed-only legacy acceptance, completion, restarts and
revocation. An established native stream on an unaffected Edge is checked across
CP promotions and other Edge replacements; it is closed before its owning Edge
is replaced. This does not assert socket recovery after destruction of its owner.

Set absolute `DSSE_AUTH_RELEASED_BINARY` and `DSSE_AUTH_CURRENT_BINARY` paths and
`DSSE_AUTH_BINARY_DSN` for an **empty, disposable** PostgreSQL database, then run:

```sh
go test ./cmd/dsse-edge -run '^TestAuthReleasedAndCurrentExecutables$' -count=1 -v -timeout=10m
```

The test refuses a database containing public tables and does not drop that database.
It stops its own child processes. The caller must remove its disposable database
or container afterward. `DSSE_AUTH_BINARY_OUTPUT`, when supplied, retains private
fixture keys and process logs; do not publish that directory.

The bootstrap uses lab mode with an explicitly armed synthetic administrative
credential and seeded completed-authentication fixtures; transport certificates and
bundle signatures are verified. It does not exercise an external IdP ceremony,
OS agents, signed installer packages, a real distributed database/quorum system,
or network partitions. Installer migration regression separately checks an existing
issuing directory without rollout material, preservation of deployment keys and
operator-inventoried baselines, and destination-only carries. These local checks do
not constitute production deployment or release approval. No cloud resources are
needed.


For user/session identity enforcement after the compatibility upgrade, see
[device user authentication](device-user-authentication.md). Its capability is
advertised by updated members but activated explicitly after endpoint and
administrator-assignment preparation.

## Policy-capped grant lifetimes

Current nodes sign positive rule/tenant grant-lifetime limits into start links
and enforce them again when reusing evidence. A modified or removed limit fails
the request signature. Encrypted recovery state carrying a cap uses payload
version 2; version-1-only Portals must reject it instead of silently discarding the
limit. Uncapped version-1 state remains readable by current nodes.

Complete the CP/Edge upgrade before validating capped authentication across every
Portal. An in-progress capped ceremony sent to an older Portal can require a fresh
start; treating an unrecognized cap or state version as unrestricted is not an
upgrade fallback. Existing endpoint URL launchers accept the additional signed
request parameter without an agent reinstall. Ordinary origin, owner, lifetime,
and duplicate-parameter checks remain in force.

## Shared-fleet Portal cutover

The historical `-step-up-portal-origins` list remains an allowlist and does not
activate shared recovery on a binary-only update. The separate
`-entrance-portal-origins` / `DSSE_ENTRANCE_PORTAL_ORIGINS` JSON map is the explicit
cutover switch. Keep it unset and keep existing owner-pinned front-door routes
while replacing CP/Edges one at a time and verifying fresh authentication through
healthy members. After all expected authenticated capability reports and
`ceremony-recovery-v1` activation, verify all-origin browser SAN certificates,
load the map on updated Edges, then reload shared front-door pools one entrance
at a time. Do not load a newly generated shared-fleet environment during the
binary-only phase. Premature explicit-map activation logs a readiness warning and
returns 503 for new starts. See the [staged procedure](releases/0.4.0/upgrade.md#changing-to-the-multiple-edge-authentication-layout).

Retaining authentication during live one-node replacement and new sign-in during
entrance-only loss are separate real-endpoint acceptance items. Local old-config
and activation regressions do not establish zero-downtime live replacement.
