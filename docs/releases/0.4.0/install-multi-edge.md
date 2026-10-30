# Three entrances with Region-scoped Edge pools

This guide describes three independent entrances, topology selection,
installation and current limitations. In the one-Region profile, each entrance
distributes browser authentication, endpoint and Connector transport to the
same three Edges. In the three-Region profile, each entrance distributes those
connections only to its own Region's Edges. Authentication grants and revocation
still propagate across all Regions. 0.4.0 is an experimental release; see
[Acceptance and limitations](verification.md) for what was measured and what
remains open.

## Topologies and implementation status

| Topology | Placement | Required distribution |
|---|---|---|
| One Region, three Nodes | Each of three hosts runs HAProxy, CP, Edge and a state member | Every one of the three independent entrances distributes to all three Edges |
| Three Regions, multiple Edges | Each Region has one dedicated CP+HAProxy host and two dedicated Edge hosts (expandable); minimum nine = three CP/HAProxy and six Edge hosts | Three entrances in the whole deployment; each physical entrance distributes to its Region's two Edges |

The required distribution includes browser authentication, endpoint transport and
Connector transport within the selected Region. Management API and Console traffic retain leader-aware CP
routing. Hostnames are shared across tenants. Agent mux behavior is unchanged;
new mux TCP connection balancing is not equal flow or bandwidth distribution.

In one Region, A/B/C all use the same three-Edge pool. In three Regions,
physical CP+HAProxy entrance A uses dedicated Edges A-1/A-2, B uses B-1/B-2,
and C uses C-1/C-2. No traffic-processing Edge runs on the CP-only hosts.
Normal DNS points each regional Portal to its matching CP entrance. Endpoint
and Connector health checks choose another permitted entrance after a Region
fails; an existing browser callback for the failed
Portal origin does not migrate to another origin.

Three state members are separate replicated databases/consensus processes, not a
shared mounted disk. Two of three votes and the database's synchronization rules
must hold. DSSE Regions are logical placement units, not geographic cloud Regions.

The three browser origins remain separate. In one Region with three combined
Nodes, every Edge serves all three Portal names and needs corresponding browser
certificate SAN coverage. In the dedicated three-Region layout, each Edge
serves its own Region's Portal name, and its browser certificate needs that
name. The signed endpoint profile still lists all three origins as failover
candidates. It does not make every Edge serve every origin. A failed Portal
hostname is not automatically taken over by another Region's entrance through
DNS, nor is an already-open browser callback moved there. Each Edge
uses a fixed, configured OIDC redirect URI for the selected origin, the shared binding key, encrypted
ceremony state and CP one-time consumption. Cross-origin substitution, replay and
unknown Host/SNI are refused. Management and Console routing stay leader-aware.

The installer generates regional backend pools for the three-Region profile.
The released images were installed in that profile on Linux hosts with real macOS
and Windows endpoints; see [Acceptance and limitations](verification.md). The
one-Region profile has not been installed from the released images.

## Install one Region with three combined Nodes

Use profile `one-region-three-nodes` and
[its plan](../../plans/one-region-three-independent-entries.json).
`one-region-multi-edge` remains the separate single-entrance, dedicated-Edge profile;
it does not replace this three-combined-node topology.

### Prepare tools, machines and the plan

Prepare three Linux hosts, persistent disks, Docker/Compose v2, synchronized time,
private IPv4 peer routing, stable DNS and verified SSH host keys. IdP/Connector
fixtures are additional infrastructure. Test real IPv6 egress from every Edge
host and container before enrolling dual-stack endpoints. Use source, images and
installer from one reviewed revision. Follow [Building](../../building.md) for the two
first-party service images and preload required third-party images. Carries do not carry images.

```sh
export GOTOOLCHAIN=go1.27.3
mkdir -p bin
go build -buildvcs=false -trimpath -o bin/dsse-install ./cmd/dsse-install
go build -buildvcs=false -trimpath -o bin/dsse-profileverify ./cmd/dsse-profileverify
go build -buildvcs=false -trimpath -o bin/dsse-deployment-crl ./cmd/dsse-deployment-crl
export PATH="$PWD/bin:$PATH"
cp docs/plans/one-region-three-independent-entries.json plan.json
```

Replace the deployment suffix, verified package publisher (`agent_publisher`),
reviewed source identifier (`image_revision`), optional immutable image references, Node names, three
Portal names, private bind addresses, reachable peer TLS names/addresses and
actual failure domains. Each Node holds `["control-plane", "edges"]`; there is
one DSSE Region and one founding Region. The sample uses Region `kiri` and
Nodes `node-a`, `node-b`, `node-c`.

Every plan must set `data_layer` with immutable `etcd_image`, `postgres_image`,
and `postgres_tools_image` references plus `postgres_major: 18`. The 0.4.0
release publishes these images; their digests are listed in the
[release README](README.md#server-container-images). Use the same
reviewed cohort on every machine and make the images available to each Linux
host. The sample plans omit this release-specific field: add it before
`-preflight` or `-start-node`. The installer carries these values; setup
preflight refuses an omitted cohort and checks the actual PostgreSQL binary
major before startup. Generated Compose also requires explicit data-layer image
references and has no legacy fallback. Use `-preflight` and `-start-node` to
verify the actual images before starting services. See [Building](../../building.md).
Replace the sample `service_image` and `console_image` local tags with the
published digests, or with images you built, and set `image_revision` to match. The release image gate checks
both completed supported plans against every scanned built image.

### Using the published images

To install the released images, put these values in the plan before generating
the deployment directory. They are the images the release acceptance ran. They
are linux/amd64 only, so every host must be x86-64; on an arm64 host `-preflight`
refuses them, and you build the images from source instead (see
[Building](../../building.md)). The HAProxy and ClickHouse images the installer
pins cover both architectures:

```json
"image_revision": "source-768a8c72fb96156d00d2e78d6a0f3903b506f59c988e5692c2e951efd6ddd6f8",
"service_image": "ghcr.io/lantern-networks/dsse-service@sha256:9d7d0f62365c59398dc3ea83ef09aab67e1650cd22a395d197047ff9cb6a5118",
"console_image": "ghcr.io/lantern-networks/dsse-console@sha256:bd729ef7776cb38c53d149dcf69e8471c95a580e9213cbce0ed6f6f0268a9c97",
"data_layer": {
  "etcd_image": "ghcr.io/lantern-networks/dsse-etcd@sha256:0c85129c93c3dcd0bb4d00c44c8cb7db749c256f36d39fbcf323b9bfaab0c24f",
  "postgres_image": "ghcr.io/lantern-networks/dsse-postgres@sha256:7b6559a1ffd064428cd11b5e3a041fa1ad97d433e0f77f1718f70ede00b11396",
  "postgres_tools_image": "ghcr.io/lantern-networks/dsse-postgres-tools@sha256:2285f9b3ca3b949b9113fd8564715777466c1d9d1ee21690ccb29667df5dfc74",
  "postgres_major": 18
}
```

The installer does not pull images; `-preflight` refuses an image that is not
already on the host. On each host, once its deployment directory
exists (the founder's generated directory, or an unpacked carry) and before
`-preflight` or `-start-node`, pull exactly the images that host's generated
Compose file uses. No registry sign-in is needed:

```sh
cd <deployment-directory>
docker compose --env-file deployment.env config --images
docker compose --env-file deployment.env pull
```

In three Regions a CP+HAProxy host lists seven images: the five above and the
HAProxy and ClickHouse images the installer pins. A dedicated Edge host lists only
`dsse-service`. Then check what was pulled:

```sh
docker image inspect --format '{{json .RepoDigests}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
  ghcr.io/lantern-networks/dsse-service@sha256:9d7d0f62365c59398dc3ea83ef09aab67e1650cd22a395d197047ff9cb6a5118
```

The digest must be the one in the plan, the [release README](README.md#server-container-images)
and `release-manifest.json`, and the revision label must equal `image_revision`.

To enroll endpoints with the published signed packages, set `"agent_publisher":
"M4U8GSBL6C"`, the Apple Team ID that signs the macOS package. A plan carries one
publisher; the acceptance installation used this value for both the macOS and the
Windows endpoints. Validating Windows agent updates against it is an open item.
`-preflight` repeats the label check and also checks each image's OS and
architecture and the service binary's own revision. To check the images'
source, see [Checking the images yourself](README.md#checking-the-images-yourself).

For deployment-certificate Online revocation, declare `deployment_crl_origins`
**before minting** the authority. Supply one to eight distinct, publicly reachable
plain HTTP origins without credentials, paths, queries or fragments, for example
`"deployment_crl_origins": ["http://crl-a.example.invalid", "http://crl-b.example.invalid"]`.
Replace these example names with the real operator-controlled origins. The
installer binds each issued certificate's CDP to its issuer and deployment; an
omitted list retains legacy certificate material and does not pass the Online
revocation release gate. The browser Portal certificate and external IdP chain
need their own issuer-provided Online revocation status.

Choose audit storage in the plan before minting. The sample selects **local-only retention**:
leave `archive` absent and provision persistent hot-store capacity,
monitoring and backups on CP state hosts. No S3 endpoint or credentials are required;
aged hot events remain local, with no S3 Object Lock or cold archive. Passing a
retention period does not automatically delete local logs in this mode. The
Admin Console states this and does not offer retention-day controls; operators
must monitor capacity and maintain backups. Explicit, scoped manual deletion is
a separate administrative action. For an
**external archive**, add an `archive` object with your operator-managed, private
S3-compatible endpoint, bucket, Region and `auth_mode` (`static` or `iam`). Provision TLS, versioning
and Object Lock before startup, and include CP-to-bucket TLS egress in the firewall
plan. Never give customer tenant administrators bucket credentials or direct object
access. An archive-enabled plan does not create the bucket.
Before accepting local-only retention, rehearse an isolated backup and restore
for the exact deployed image and schema. The repository's
`scripts/verify_local_audit_restore.sh REPORT_DIR` exercises the audit store
with synthetic records; also back up and restore the real deployment's authority,
PostgreSQL, configuration and Edge spools as described in
[Operations](../../operations.md#backups-and-recovery-preparation).

```sh
export DSSE_PLAN="$PWD/plan.json"
export DSSE_DIR=/opt/dsse
umask 077
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -order > install-order.txt
dsse-install -plan "$DSSE_PLAN" -client-hosts client-hosts.txt \
  -entry-ip 203.0.113.10 \
  -node-entry-ips node-a=203.0.113.10,node-b=203.0.113.11,node-c=203.0.113.12
```

The plan's optional `shared_entry_machine` selects the host for generic names
such as `agents.<deployment>` and `recovery.<deployment>`; its default is the
founding Region's CP/L4 (Node A in this example). To put those names on Node B,
set `"shared_entry_machine": "node-b"` and set `-entry-ip` to B's declared public
address. In the dedicated layout choose a declared CP/L4, for example `cp-b`.
The generator and host verifier reject a generic address belonging to another
host. Generic aliases must have that one selected entrance; arbitrary round-robin
or geo DNS for them is outside this map contract. Prefer the three explicit
entrance names for agent failover.

Replace these reserved IPs with the three independent entrance addresses. Publish
all generated names through controlled DNS/hosts distribution and resolve private
peer names from containers. Read the generated numbered order as host-specific
instructions, not an executable shell script; its step count depends on the plan.

### Provision approved Portal TLS and start Node A

Mint only on Node A. Protect and back up this issuer; never use `-force` to
recover a failed installation. DNS, firewall, IdP and approved certificates are
operator inputs; the installer does not obtain them or request OS approval.
Edit only documented operator inputs in the private generated `deployment.env`;
do not alter generated Compose, launchers or computed plan values to make a check pass.

```sh
dsse-install -plan "$DSSE_PLAN" -network-plan > network-requirements.json
sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$DSSE_DIR"
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -organization "Example Operator"
dsse-install -install-portal-certificate /secure/portal-fullchain.pem \
  -portal-key /secure/portal.key -dir "$DSSE_DIR"
# For an explicitly approved private browser CA, add -portal-ca /secure/browser-ca.pem.
# Establish that CA's trust separately in endpoint browsers; do not fetch trust from the server.
```

If `deployment_crl_origins` is set, install the reviewed
`dsse-deployment-crl` host binary at `/usr/local/bin/dsse-deployment-crl`
and route every declared HTTP origin to the generated keyless publisher on
`127.0.0.1:18081`. Then, on the founding issuer host, run:

```sh
sudo install -m 0755 bin/dsse-deployment-crl /usr/local/bin/dsse-deployment-crl
sudo "$DSSE_DIR/install-deployment-crl-services.sh"
```

Continue on that host:

```sh
# Only when the plan declares an external archive: edit private deployment.env now.
# For static auth, set DSSE_ARCHIVE_ACCESS_KEY and DSSE_ARCHIVE_SECRET_KEY.
# For iam with injected temporary credentials, set DSSE_ARCHIVE_AWS_ACCESS_KEY_ID,
# DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY and DSSE_ARCHIVE_AWS_SESSION_TOKEN.
# For a host role, verify metadata is reachable from the CP container.
# Leave all DSSE_ARCHIVE_* fields empty for local-only retention.
dsse-install -preflight -dir "$DSSE_DIR"
dsse-install -start-node -dir "$DSSE_DIR" -machine node-a
cd "$DSSE_DIR"
```

For a declared CRL plan, run the generated activation command **after minting, before `-preflight` or
`-start-node`**. Activation requires root, but signed-CRL renewal runs as the
deployment directory's owner on that Linux host. Keep that account available.
The original issuer keys and revocation ledger remain the only signing state;
activation does not copy them or change their ownership or private permissions.
Revoke and renew against the original deployment directory as its owner.
Only the six public issuer certificates are copied into root-managed
`/var/lib/dsse-deployment-crl/<root-fingerprint>/`. A separate unprivileged,
keyless HTTP publisher reads those certificates and the live signed CRLs;
it must not receive issuer keys. The operator's
public HTTP frontends must route each declared origin's fixed CDP path to that
publisher. Verify the signed issuer CRLs are reachable and current from every
origin, including during an entrance outage. `-preflight` checks the actual
issued chains and Online CDP responses and refuses unavailable, stale or revoked
status. Publishing CRLs once without renewal is not sufficient.

The generated publisher runs only on the founding issuer host. Multiple origin
names routed to that one host do not survive its outage. A deployment that
requires Online revocation during a founding-host failure also needs an
independent read-only publication path for current signed CRLs and their public
issuer certificates. Replicate no signing key or revocation ledger. That path
is an operator-supplied prerequisite, not an installer-generated service on the
other CPs. Before accepting endpoint failover, stop the founding host and verify
a fresh strict Online revocation lookup through the surviving public origin.

In the one-Region, three-combined-Node topology, each Edge's browser leaf must
cover all three Portal names. In the dedicated three-Region topology, each
Edge's leaf must cover its own Region's Portal name. The leaf must
match its key, carry intermediates, be current, and chain to system or explicitly approved trust.
Separate keys per Edge are allowed. Import validates all of this before writing
`clientless/` and the operator-certificate contract. That contract reaches both
CP profile issuance and Edge execution. CP-only hosts record the contract without
receiving an Edge browser key. Import before initial startup, or during a planned
maintenance stop; pair files are individually durable, not a live atomic rotation.

With a private `-portal-ca`, the Edge launcher passes `clientless/trust.pem` as
`-clientless-tls-ca` for Portal certificate self-verification only. It does not set
`SSL_CERT_FILE`, change the OS store, or add that CA to application, SWG or IdP
trust. Organization application anchors and each IdP connection's CA remain
separate inputs. Browser trust still has to be provisioned independently.

When running the generated fleet `-verify` command on a CP-only host with a
private browser CA, add `-portal-ca /secure/browser-ca.pem`. Transfer only the
approved public CA bundle to that verifier host, never an Edge's browser private
key. This input is used only for the directed Portal TLS checks and is not saved
or added to OS, deployment, application or IdP trust. Without that input, the
verifier uses the local `clientless/trust.pem` when present and system roots.
Three-Region verification requires each entrance to serve its own Portal and
refuse the other two Regions' Portal names; it does not require every Edge
certificate to cover all three names.

`-preflight` uses the carried `install-plan.json` if `-plan` is omitted. It checks
local generated inputs, publisher, assigned bind IPs, peer/entrance DNS, required
mounted files, Linux Docker/Compose, preloaded image OS/architecture, first-party
OCI revision labels, the service binary's revision and Portal trust in the actual
service image. It never pulls an image, starts fleet services or changes DNS,
firewall or OS trust. Its disposable image probes use no network or issuing keys.
`ready_to_start: true` and exit 0 are required. It cannot prove a remote route,
physical storage durability, backups or IPv6 egress; verify those prerequisites.

`-start-node` repeats preflight and runs only this node's Compose `up -d` after
success. Optional certificate flags can be supplied to that command too. A failed
check starts no services. `compose_started: true` means Compose returned success,
not that the database/authority is ready. Read the failing check, fix its input and
rerun the same node command. On partial Compose failure, inspect `docker compose
-p <printed-project> --env-file deployment.env ps` in that directory; state is
retained, never deleted or reminted automatically.
When an external archive is configured, carry the founding CP's dedicated archive
credentials to other CP hosts through the generated protected carry. Preflight's
read-only bucket check does not prove Put permission or container IAM reachability.
Before declaring archive acceptance, verify one real archived batch and object
retrieval, then monitor failures and hot-store growth. A configured archive outage
retains pending hot rows locally; it does not silently switch to an unverified
archive. The local-only choice does not run an archive check.

If you choose external S3, add this plan shape with your own endpoint, bucket and
HTTPS alert receiver; keep archive credentials and the webhook signing secret out
of the plan in the private `deployment.env`:

```json
{"archive": {"endpoint":"objects.example.invalid:443","bucket":"my-private-audit-bucket","region":"my-region","auth_mode":"iam","webhook_url":"https://alerts.example.invalid/dsse"}}
```

Use `"auth_mode":"static"` only with dedicated least-privilege archive keys in
the private `deployment.env`. Neither mode gives customer tenant administrators
direct S3 access.

### Bootstrap and close emergency credentials

For three-voter profiles, closing bootstrap intentionally fences CP startup and
writes until all three planned store voters have joined. CPs can temporarily
restart or return unavailable during that initial sequence. Keep the closed marker
and continue the documented store/DB joins; do not reopen bootstrap, weaken quorum
or wait for full CP readiness before admitting the next state member. Require CP
readiness after the third promotion, before authentication activation.

Wait for verified CP health at the exact URL printed in `install-order.txt`.
Health is necessary but does not by itself prove write authority. On Node A:

```sh
curl --fail --show-error --cacert "$DSSE_DIR/deployment-anchor.pem" \
  https://admin.kiri.example.test/healthz
(umask 077; set -C
 dsse-install -bootstrap-admin -dir "$DSSE_DIR" \
   -control-plane https://admin.kiri.example.test -admin-email admin@example.invalid \
   -admin-token-file "$DSSE_DIR/authority/operator-api-token" \
   > "$DSSE_DIR/admin-credentials.txt" 2>&1)
```

Require exit 0 before the next step. The output file is private and is not
clobbered; inspect and retain it on failure. Bootstrap reserves its token output
without overwrite before API mutations. The named operator token stays in the
issuer's `authority/` and is not printed on success or copied into a carry.
Retain the displayed password, TOTP and recovery codes securely. An interrupted
bootstrap that already created an account requires recovery using the retained
output and the [bootstrap recovery procedure](../../deployment.md); do not delete
an existing token or marker to retry blindly.

For multi-Edge plans, bootstrap also reserves and saves a separate 0600 file,
`authority/installation-state-read-token`, using the named administrator's session.
Its only scope is `admin.state.read`, with role `admin`; it cannot activate
features, edit policy, manage tenants or issue tokens. Its lifetime follows the
existing API-token policy (90 days if no expiry is supplied); manage or replace it
through a named administrator. Neither credential belongs in runtime-node carries.

Run printed step 4 to recreate CP and Edge, then the L4 doorway, closing bootstrap
and refreshing its backend. For the combined example:

```sh
docker compose -p dsse --env-file deployment.env up -d --no-deps \
  --force-recreate dsse-control-plane-a dsse-edge-a
docker compose -p dsse --env-file deployment.env up -d --no-deps \
  --force-recreate dsse-edge
```

### Admit Nodes B/C, verify synchronization, activate authentication

Follow printed steps 5–14: add B as an etcd learner, pack/copy B individually,
start B, wait for catch-up and promote; then repeat for C. Failed promotion does
not mean “add again”: inspect `member list`, allow catch-up and retry promotion.
Never run a duplicate `member add` blindly. After promotion, membership health
may take a short time to converge. With the same generated `etcdctl` prefix, run
`endpoint health --cluster` and `member list`. If the next add returns
`unhealthy cluster`, inspect whether its intended peer is already listed, wait
for healthy membership and retry only the operation that was not committed. On A:

```sh
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -carry node-b.tar.gz -machine node-b
scp node-b.tar.gz operator@node-b.example.test:
```

On B, preload the reviewed images, then:

```sh
umask 077
mkdir -p /opt/dsse/kiri
tar xzpf node-b.tar.gz -C /opt/dsse/kiri
# If using a distinct Edge key, import its approved all-Portal SAN pair here.
dsse-install -start-node -dir /opt/dsse/kiri -machine node-b
```

The carry retains the complete plan and closed-bootstrap marker, never issuing
keys or the operator token. Protect and retire temporary carry copies. After all
three voters and database members join, run printed strict synchronization:

```sh
cd /opt/dsse
docker compose -p dsse --env-file deployment.env exec -T dsse-postgres-a \
  patronictl -c /home/postgres/postgres.yml edit-config dsse \
  --set synchronous_mode=true --set synchronous_mode_strict=true \
  --set synchronous_node_count=1 --force
docker compose -p dsse --env-file deployment.env exec -T dsse-postgres-a \
  patronictl -c /home/postgres/postgres.yml show-config dsse
docker compose -p dsse --env-file deployment.env exec -T dsse-postgres-a \
  patronictl -c /home/postgres/postgres.yml list dsse
```

Require `synchronous_mode: true`, `synchronous_mode_strict: true`,
`synchronous_node_count: 1`, three database members, one Leader and at least one
streaming Sync Standby. On each CP host use its printed project (`dsse` on A,
`dsse-kiri` on B/C) and deployment directory to run the same `show-config`/`list`.
Run the final generated `-verify` command as well: its authenticated authority
checks measure the actual `pg_stat_replication` state, quorum and CP views. Failed
or unmeasured checks do not count as synchronization acceptance.

Before endpoint authentication, run the new printed activation step on A:

```sh
dsse-install -activate-auth -dir /opt/dsse \
  -admin-token-file /opt/dsse/authority/operator-api-token
```

The issuer reads `authority/installation-state-read-token` automatically. The
operator credential is used only at the CP authority during this command. Before
contacting any Edge, it verifies the separate reader at the CP's `/admin/session`
and requires exactly `admin.state.read`. Only that reader is sent to Edge status
endpoints; there is no fallback to the operator token. A missing, expired or
broader credential stops setup.

For a deployment bootstrapped by an earlier installer, sign in as a named
administrator and create an API token with role `admin`, exactly the
`admin.state.read` scope and an appropriate expiry. Save its value in a protected
0600 file and supply `-edge-read-token-file /secure/installation-reader`. Do not
delete the bootstrap marker, re-arm emergency access or substitute the operator
credential. An API token cannot create another token; that protection is unchanged.

Require exit 0, `phase: ready`, no waiting members and `applied_edges: 3` (6 for
the minimum three-Region dedicated plan). It reads the complete generation and
preserves all existing enabled features. It waits for fresh authenticated reports
from all active CP/Edge members, uses the existing activation authority, then
checks that every declared Edge applied the same manifest and enabled features.
Timeout is not success: fix the listed member and rerun; completed activation is
not repeated unnecessarily. Do not change the census to omit a failed node.
Device/user binding remains explicit after assignment/endpoint preparation;
see [authentication upgrades](../../authentication-rolling-upgrades.md).

After `phase: ready`, revoke an unused installation reader through the CP using
a named administrator once no further setup checks or monitoring need it.
Deleting its private file alone does not revoke the credential. If activation
verification is needed again, provision a new `admin.state.read`-only reader as
described above; never substitute the operator token.

For rolling-update monitoring, read `auth_rollout` on the authenticated
`GET /admin/config-sync-status` route using a state-read credential. Anonymous
`/healthz` retains readiness and basic configuration-pull diagnostics, but does
not expose authentication rollout status or prove authentication activation.

The final verifier measures Portal TLS separately. In one Region with three
combined Nodes, test all three Portal origins at all three entrance addresses:
nine directed TLS checks. In three Regions with dedicated Edges, test the
three matching entrance/Portal pairs and reject a foreign Portal SNI at each
regional entrance. Use approved trust and the correct SNI. This is a server TLS test, not proof
of client DNS selection, which physical CP and Edge handled a connection,
automatic Region failover, or an IdP/browser round trip. A missing entrance,
SAN, or trust chain fails.
Unperformed browser, endpoint and failure acceptance is explicitly `n/a`, never
PASS; it remains mandatory before device admission. Review every
`n/a` even when the measured server checks exit 0.

On a CP-only verifier host, an approved private browser CA must be trusted by the
host's normal CA store (one approved CA per file on Ubuntu's
`/usr/local/share/ca-certificates/`, followed by `sudo update-ca-certificates`).
This is public trust material only; never copy an Edge private key to the CP.
Edge/combined hosts also use the explicit trust saved by certificate import.

Finish with the entire generated `-verify` command, now using the private token
file rather than a token in shell history. On each entrance host also inspect
`sudo dsse-install -verify-proxy-resources -dir <deployment-directory>`. Finish
Console login, tenant/IdP/Connector setup, signed endpoint enrollment and actual
allow/deny/browser resumption checks. `ready_to_start`, `compose_started`, and
activation `ready` are three distinct milestones; none replaces live acceptance.

## Network, browser authentication and endpoints

`-network-plan` lists plan-derived private TCP destinations and source machines.
Apply it using your controlled firewall process; never expose private rows to the
Internet. Separately allow DNS, time, IdP/OIDC, online certificate revocation,
registry access while preparing images and policy-approved application egress;
those destinations are not inferred from the topology. Preflight DNS success does
not establish cross-host TCP reachability. In one Region, allow every entrance
to all three Edges. In three Regions, allow each entrance to its own Region's
Edge traffic/health ports (8443/9443),
verified Node relay and the generated private CP/consensus/database replication
paths. Keep private services off the Internet. Trust PROXY metadata only from
declared entrances. Preserve tenant, residency and authorization restrictions.
Verify Portal/Console/IdP names, complete chains and required online revocation;
do not accept installation by disabling certificate verification.

Register the exact three Portal callbacks ending `/clientless/auth/callback` and
include all three legitimate origins in the signed endpoint profile for Region
failover. In one Region with three combined Nodes, each Edge's browser-trusted
leaf must cover all three Portal names. In three Regions, each dedicated Edge's
leaf must cover its own Region's Portal name.
Include intermediates and the same deployment binding secret. A separate key
per Edge is allowed. On each Edge host run
`dsse-install -verify-portal-certificate -dir <deployment-directory>`; it must
check the names served by that Edge, approved trust and current validity. The
combined-node full `-verify` includes the same check.

Multi-Edge browser starts require a verified endpoint binding and active
`ceremony-recovery-v1`; anonymous process-local clientless starts are refused.
The explicit `DSSE_ENTRANCE_PORTAL_ORIGINS` JSON map generated by the installer
lists the approved outer endpoint/Connector TLS SNI names on all Edges. In one
Region with three combined Nodes, its SNI-to-Portal selection is unchanged. In
three Regions with dedicated Edges, an approved SNI starts a **new** ceremony
at the processing Edge's own regional Portal, even if failover carried an SNI
associated with a different Region. With the normal DNS/EIP mapping, entrance
A's name reaches physical CP+HAProxy A, one of its two dedicated Edges processes
the request, and Portal A is selected. A regional SNI name alone does not prove
which physical CP received the connection: past HAProxy configuration also
accepted other Regions' agent/recovery SNI and sent them to the receiving CP's
local Edge pair. Verify DNS/EIP, receiving CP, processing Edge and selected new
Portal in the same measurement.
The mux upgrade and decrypted
HTTP forwarding retain that transport identity;
HTTP Host, forwarded headers and the internal application's SNI cannot replace
it. An unmapped transport SNI refuses new authentication with a diagnostic; it
does not fall back to the processing Edge's own Portal. Custom transport aliases
require an explicit approved map and matching DNS, certificates and L4 routing.

The explicit map enables multi-Edge authentication admission. Before capability activation the
Portal returns unavailable rather than starting an unrecoverable ceremony.
An existing three-origin trust list alone does not enable this admission rule;
use the [staged upgrade procedure](upgrade.md#changing-to-the-multiple-edge-authentication-layout)
for an existing deployment.

Use `-activate-auth` above to inspect all expected reports, activate through the
existing authority and confirm every Edge. The separate device/user opt-in requires
trusted OS-user/IdP assignments. See
[authentication upgrades](../../authentication-rolling-upgrades.md) and
[device-user authentication](../../device-user-authentication.md).

Enroll Connectors using the Console site's profile and verify the installed
runtime. Install generic signed endpoint packages using separately verified
customer profiles/pins/enrollment tokens and the [Mac](../../macos-agent.md) or
[Windows](../../windows-agent.md) guide. Private application policy belongs in
Connector Access. Test allow/deny, IPv4/IPv6, sign-in and actual native resumption,
sharing/revocation, Node failure and normal-network recovery.

## Console navigation follows the active CP

Generated CP environments include an explicit Console leader-routing map. On a
normal page navigation the Console verifies direct private CP `/leader` probes
and serves through the current origin when already running on the active CP.
Another regional or shared entrance may have routed the request there; it must
remain usable even if the active CP's own public entrance is down. Only a standby
Console temporarily redirects to the active CP's configured public Console origin.
It does not forward API writes, login tokens or activation/callback queries.
Host-only sessions may require another sign-in after a hostname change. An
unconfirmed or ambiguous leader produces a retry page instead of a guessed
redirect. Existing one-Region names continue to use leader-aware HAProxy routing.
For acceptance, stop only the active CP host's public HAProxy while keeping that
CP leader running. Verify sign-in and authorized revocation through the remaining
two entrances and a shared name resolved to a surviving entrance. Writes must
remain on that origin without a redirect or replay.
Rebuild/recreate the Console service and apply the regenerated per-host environment
to enable this on existing deployments. See the [Console guide](../../../console/README.md#follow-the-active-control-plane)
for configuration, browser TLS, loop prevention and failure behavior.

## Extend to three Regions with regional Edge pools

Use [the dedicated plan](../../plans/three-regions-multi-edge.json):
each Region has one dedicated CP+HAProxy host and two dedicated Edge hosts.
`cp-a`, `cp-b`, `cp-c` each run CP/HAProxy/state, and `edge-a-1` through
`edge-c-2` are Edge-only hosts. A separate IdP/Connector test fixture is not
one of these nine product hosts. The generated `dsse-edge` Compose service on
a CP host runs the HAProxy image; the traffic-processing `dsse-edge-a` service
runs on a dedicated Edge host. Add further declared Edge-only hosts if required.
Each CP/L4 derives only its own Region's Edge list; a CP-only host never
acquires a fictitious local Edge. Inspect the generated HAProxy backends and
verify local-only routing before using this profile for an installation.

```sh
cp docs/plans/three-regions-multi-edge.json plan.json
# Edit all names, private addresses and actual failure domains first.
export DSSE_PLAN="$PWD/plan.json"
export DSSE_DIR=/opt/dsse
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -order > install-order.txt
dsse-install -plan "$DSSE_PLAN" -client-hosts client-hosts.txt \
  -entry-ip 203.0.113.10 \
  -node-entry-ips cp-a=203.0.113.10,cp-b=203.0.113.11,cp-c=203.0.113.12
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -organization "Example Operator"
```

The minimum layout uses nine hosts. The generated order is authoritative for its
steps, host-specific ports, Compose projects, learner admission, promotion and
strict synchronous database configuration. A plan with `deployment_crl_origins`
also includes the issuer's CRL renewal and keyless HTTP publisher before node
startup; do not rely on a fixed step count. Start
and bootstrap CP A; admit CP B/C one at a time; verify all three voters and strict
synchronization **before** starting the dedicated Edges. Carry each host by its
exact plan name, for example:

```sh
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" \
  -carry edge-b-1.tar.gz -machine edge-b-1
# On edge-b-1, after private transfer and image loading:
umask 077
mkdir -p /opt/dsse/region-b
tar xzpf edge-b-1.tar.gz -C /opt/dsse/region-b
cd /opt/dsse/region-b
dsse-install -start-node -dir /opt/dsse/region-b -machine edge-b-1 \
  -install-portal-certificate /secure/portal-fullchain.pem -portal-key /secure/portal.key
```

Use the printed carry/start command for every remaining host. Supply a browser
SAN pair covering that Edge's regional Portal name before starting it. Do not copy the issuing directory or
state-member credentials to Edge-only hosts. Configure IdP callbacks for
`https://portal.region-a.<deployment>/clientless/auth/callback`, and likewise
Region B/C. There are three origins regardless of Edge count or tenant count.

Allow each CP/L4 private source to reach its own Region's Edges on 8443/9443,
plus separately verified Edge relay paths. Restrict trusted PROXY senders to
the CP/L4 addresses actually allowed to connect. Do not replace that list with
a broad subnet or disable PROXY-source validation. Review the generated private
network plan against the regional backend list before deployment.

The L4 cannot select a tenant-specific backend from an encrypted tenant
identity. Endpoint and Connector failover must select only a permitted Region;
an out-of-boundary Edge continues to refuse the tenant. Do not widen
`allowed_regions`, change `home_region` semantics or advertise that failover
bypasses residency. Unknown placement also fails closed. CP authority routing
remains independent of this Edge admission check. The tenant settings APIs return HTTP 409 with
`shared_fleet_residency_confirmation_required` before saving a newly narrowed
boundary. Review the availability impact, then explicitly resubmit with boolean
`acknowledge_shared_fleet_residency_impact: true` if that restriction is intended.
The Console presents that confirmation and warns about existing conflicts.
Unrelated edits to an unchanged boundary remain possible; missing fleet inventory
blocks new restriction changes. Confirmation never widens the boundary or makes
an out-of-Region Edge accept the tenant.

### Processing location and Internet source addresses

Each entrance uses Edges in its own Region. Add every participating Edge's
effective public IPv4 and IPv6 egress address (including NAT addresses where
applicable) to SaaS/IP allowlists and verify both address families. Account
for location-based SaaS decisions after endpoint or Connector Region failover.
The selected Region can change after a fault, so neither a fixed Internet
source address nor a latency bound is implied.
Tests in one cloud geographic Region do not establish performance across
geographically separated Regions.

For later Edge admission, update the complete plan and explicitly admit the new
member in the authenticated capability census first. `-add-edge <name> -plan ...
-dir ...` must regenerate only the affected Region's CP/L4 backend pool; update
other generated settings only where required by the plan. It neither
restarts services nor bypasses census generation checks. Verify all members and
health/TLS, then reload each HAProxy; no automatic remote fan-out is performed.

Acceptance must confirm each entrance routes only to its own Region's Edges for
transport, Connector and browser authentication separately, then test ceremony-owner loss,
revocation, Region/CP failure and rejoin. Losing an entrance host is different from
losing an Edge behind it. Specifically stop an entrance/CP-L4 alone while its
Region's Edges remain healthy; require fresh authentication via each surviving
entrance from both OSes, and verify the selected Portal follows the actual
entrance. Start a fresh authentication request after Region failover; do not
claim that an already-open callback on the failed Portal origin migrated.
This independent-entry design does not move public IPs
or migrate established sockets. Preserve failures and qualification limits in
[the release acceptance record](verification.md).
