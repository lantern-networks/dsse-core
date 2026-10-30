# Install 0.4.0

0.4.0 is accepted as a fresh installation. Existing 0.3.1 deployments,
if any, need separate validation of upgrade and data migration, including any
previously bundled object-store data. The legacy upgrade procedure below is
reference for a future supported upgrade and is not part of 0.4.0 acceptance.

## New deployment

Use the [three-entrance installation guide](install-multi-edge.md) for the
complete host-by-host workflow. The checklist below also applies to upgrade planning.
The one-Region shared pool and three-Region regional pools have different
routing contracts. Both were installed from the released images with real
endpoints; [Acceptance and limitations](verification.md) lists what remains open.

1. Read the release manifest and the open acceptance items. Verify source
   and package checksums, platform signatures, notarization or Microsoft driver
   signature as applicable. Use source and tools from the same release.
2. Build the operator tools using [Building](../../building.md). Use the
   [published images](install-multi-edge.md#using-the-published-images) or build them.
   Choose the [three-region dedicated-node plan](../../plans/three-regions-multi-edge.json)
   or the [one-Region three-node plan](../../plans/one-region-three-independent-entries.json). Supply your
   own failure domains, network addresses and signing identities.
   Choose local-only audit retention or an optional external S3 archive. For the
   latter, provision the private bucket and CP credentials before startup as
   described in the installation guide; older bundled object-store data is not
   migrated automatically.
3. Follow [the generated installation order](../../three-regions-multi-edge.md#plan-and-installation).
   Establish the state quorum and required database synchronization before starting
   dependent Edges. Preserve the original issuing directory and protect its keys.
4. Configure tenant policies and IdP callbacks for the common regional Portal origins.
   Adding a tenant must not generate another set of plane hostnames. Keep internal
   application access in Connector Access and Internet policies in Internet Access.
5. Verify complete browser TLS chains for Portal, IdP and Console; verify the required
   online revocation behavior. Distribute only the intended deployment trust roots.
   Test IPv4 and IPv6 egress from every Edge before enrolling IPv6-capable endpoints.
6. Install the generic signed PKG/MSI using external signed provisioning inputs.
   Verify actual device identity, OS permissions, steering, policy and normal recovery.
   Do not disable certificate verification to complete enrollment.
7. Inspect the expected CP/Edge capability census. Enable supported authentication
   features only after all required members report and endpoint/user assignments are
   prepared. Test a real native request, browser confirmation, IdP authentication,
   held-request resumption, reuse, revocation and a failure before relying on the fleet.

## Upgrade from 0.3.1

This is reference material only, not a supported or tested 0.4.0 upgrade
procedure. PostgreSQL 16 to 18 requires a major-version data migration such
as [`pg_upgrade`](https://www.postgresql.org/docs/current/pgupgrade.html) or dump and restore. etcd 3.5 to 3.7 requires [supported
one-minor-version-at-a-time upgrades](https://etcd.io/docs/v3.7/upgrades/upgrading-etcd/). Neither migration is included or
validated by this procedure; do not apply it to existing state.

Plan a staged, one-node-at-a-time update that keeps authentication available
through healthy nodes. Prepare backups and recovery separately; a maintenance
window is not permission to stop all new authentication during feature activation.
Read [authentication rolling upgrades](../../authentication-rolling-upgrades.md)
for the exact storage, membership and compatibility contract.

- Inventory every CP, Edge, Connector and endpoint version, including offline nodes,
  original deployment keys, IdPs, user mappings, current configuration and databases.
  Create and verify a protected, consistent backup and a full-fleet recovery plan.
  Never assume a missing member has already upgraded.
- Treat the tenant-boundary fix as a security update. Assess prior exposure and plan
  IdP client-secret rotation, token/session invalidation and reauthentication as
  applicable. Do not include secrets or grants in support bundles or release assets.
  These notes are not a security advisory.
- Build from one reviewed revision. Generate a complete operator-inventoried rollout
  census with individual process identities. A standalone new-install census does
  not establish the versions or membership of an existing multi-node deployment.
- Upgrade the authority and signed distribution path before new Edges depend on it.
  Preserve quorum, drain owning processes, and allow interrupted applications to
  reconnect. Capability completion requires fresh reports from all nonretired members.
  Do not declare completion from just the nodes currently online.
- New/old TCP peers negotiate compatibility. A retained 0.3.1 Connector can still
  impose its original limits; mixed operation does not provide the complete new
  resource behavior. Update Connectors as part of the maintenance window.
- Test agent MSI/PKG upgrade, preservation of device identity and adopted trust,
  updater publisher arguments, signed external profile handling, and recovery on
  actual supported endpoints. Old macOS extensions pending deletion may require a
  reboot; check the real state instead of repeatedly reinstalling.
- After authentication capability completion, individual-node rollback to released
  0.3.1 is unsupported. Do not reopen completion or restore only one database/binary.
  A rollback requires a separately verified consistent fleet/state recovery.

Real mixed-executable regression coverage exists. A future offered upgrade will
need its own signed-PKG/MSI and database-recovery acceptance evidence. No live
deployment configuration is included in these assets.

## Changing to the multiple-Edge authentication layout

The profile's historical `DSSE_STEPUP_PORTAL_ORIGINS` / `-step-up-portal-origins`
is an origin trust list. Keeping its existing three values during a binary update
does **not** activate shared-fleet authentication. The separate explicit
`DSSE_ENTRANCE_PORTAL_ORIGINS` / `-entrance-portal-origins` JSON map is the cutover
switch. The new installer generates it for new shared-fleet deployments; do not
load that new environment wholesale during the binary-only stage of an upgrade.

1. Retain each existing owner-pinned Portal route and its current agent routes.
   Back up plan, environment, TLS material and the complete capability census.
   Keep the entrance map **unset** on all participating processes. Upgrade CP and
   Edges one at a time, draining each process, checking health and testing a fresh
   authenticated native request through a remaining healthy owner after each step.
   Preserve tenant boundaries, device identity and the shared binding secret.
2. Require fresh authenticated reports from every expected CP/Edge. Verify the
   shared ceremony key and CP atomic result authority, and activate
   `ceremony-recovery-v1` with the complete intended feature set through
   `/admin/auth-rollout`. A listening port or a report from only online members
   is insufficient. Keep owner-pinned routing during this stage.
3. In one Region with three combined Nodes, provision each Edge's browser-trusted
   SAN chain for all three Portal names. In three Regions with dedicated Edges,
   each Edge needs its own Region's Portal name in that chain. Include all three
   origins in the signed endpoint failover profile; that candidate list does not
   make each Edge serve every Portal. In the three-Region topology, keep each
   physical CP/HAProxy's backend limited to its own Region's Edges.
   Run `dsse-install -verify-portal-certificate -dir <deployment-directory>` on
   every Edge. Generate the same complete approved SNI map from the reviewed
   plan on all nodes. In three Regions, each Edge uses its own regional Portal
   for a new ceremony after validating a listed SNI, even if an approved alias
   arrives through another physical entrance. Check `shared_entry_machine` and
   generic-name DNS before loading the map.
4. Load the explicit entrance map on the updated Edges one at a time, checking
   fresh authentication and recovery through the still owner-pinned entrances.
   Then reload each HAProxy with its complete **regional** pool, verifying each entrance
   before proceeding. Retain an unchanged healthy entrance during each reload.
   Do not route a new origin to an old process.
5. Stop **only** one entrance/CP-L4 host, leaving that Region's dedicated Edges
   healthy. From both endpoint OSes issue several new authentication requests
   through surviving entrances and verify every returned Portal is reachable.
   The stopped entrance's still-live Edges are not backends of another Region;
   a new request must select a surviving origin.
   Record selected SNI, processing Edge, Portal, confirmation, grant and original
   flow outcome. Also test both surviving entrances and generic aliases.

Setting the explicit map before recovery activation logs
`shared_fleet_recovery_not_activated` and new shared-fleet starts return 503; it
never falls back to unsafe process-local state. If pre-cutover checks fail, stop
that stage, retain/restore the prior owner-pinned routing and omit the entrance
map on those upgraded processes. Once a capability completion is persisted, do
not undo that completion or downgrade an individual process. Preserve authority
and census state. Reverting a fully activated fleet needs consistent fleet/state
recovery; a configuration change is not authorization to weaken replay checks.

Local regressions cover an old three-origin configuration during binary upgrade,
explicit-map refusal before activation and successful start after activation.
Live one-node-at-a-time replacement and entrance-only loss with real endpoints
remain release acceptance requirements; no zero-downtime measurement is claimed.
