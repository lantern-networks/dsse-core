# Three regions with multiple dedicated Edges

Each of the deployment's three entrances distributes browser authentication,
endpoint and Connector transport across the Edge fleet in its own Region.
The six Edges in the minimum layout share authentication grants and revocation,
but a single entrance does not load balance across all six.
See [the installation guide](releases/0.4.0/install-multi-edge.md) for both the
three-combined-node and dedicated-node layouts, browser SAN certificates and
capability activation.

The 0.4.0 acceptance installation used this profile with the released images; see
[Acceptance and limitations](releases/0.4.0/verification.md) for what was measured.
Use the installer and server images from the same release. Region failure,
endpoint/Connector recovery and capacity have not been accepted for this profile.

## Layout

The `three-regions-multi-edge` profile requires exactly three DSSE regions. Each has:

- One dedicated control-plane node running the regional HAProxy entrance, Control
  Plane, Console, and one member of the shared state services.
- Two or more dedicated Edge nodes, all eligible to receive new mux connections.

The minimum is nine product machines: three dedicated CP/HAProxy hosts and six
dedicated Edge hosts, with two Edges in each Region. A separate IdP/Connector
test host is not one of these nine product machines. Edge counts may differ
between regions. A DSSE region is a logical routing and placement unit, not a
cloud provider's region. Declare
separate failure domains and arrange physical isolation appropriate to the failures
you intend to tolerate.

The three state-bearing nodes form one authority deployment with three voting
members. Two votes are required. The installer orders their admission before Edge
startup and enables strict synchronous database operation after all voters join.
Do not replace that order with simultaneous startup of every machine.

Each region exposes one stable entrance. Loss of its entrance node requires
agents and Connectors to select another authorized region. This profile does not
transfer its IP to another local node. No provider-specific IP takeover, managed
load balancer, or DNS balancing is required by the generated configuration.

## Plan and installation

Start with [the dedicated-node example](plans/three-regions-multi-edge.json).
Replace its placeholder deployment name, private addresses, machine names, and
failure domains. Set the package publisher/signing identity as described in
[Deployment](deployment.md). Keep region, machine, and DNS names lowercase.

Every machine has a distinct `reachable_address` and DNS-safe `reachable` peer
name. The first `addresses` entry is its local IPv4 bind address. `reachable_address`
is the IPv4 address at which other nodes can reach its private listeners; if the
addresses differ, the operator must supply the corresponding routing and port
mapping. Do not put a public load balancer address in place of an individual peer.

Generate the instructions before provisioning:

```sh
dsse-install -plan /absolute/path/plan.json -dir /opt/dsse -order > install-order.txt
```

Run each instruction on the named machine. The output is a sequence of operator
steps, not a script to run wholesale. It includes founding the authority, joining
and promoting the other state members, enabling strict database synchronization,
and then carrying and starting dedicated Edge nodes. CP-only machines must not
run `dsse-edge-a`. Edge-only machines must not run CP, Console, or state services.

Use the final verification command printed by `-order`. It checks all three
regional entrances and each named Edge/CP management surface. The verifier also
checks the quorum and database security settings. It explicitly leaves multi-region
failure and browser acceptance unproven; a healthy response is not a failover test.

## Names and certificates

Generate the client DNS/hosts mapping with the installer from the same plan and
one entrance address per CP node. Use three distinct entrance addresses. Shared
plane names point to a chosen entrance; regional plane names point to their own
entrance. Private peer names remain resolvable between nodes. They are not client
connection candidates.

Plane names are shared across tenants. Adding a tenant does not add hostnames.
The profile rejects per-tenant additions to the generated client hosts mapping.

Each region has one common browser origin, `portal.<region-id>.<deployment>`,
shared by its regional Edges and tenants. An explicit Edge `portal` field must equal
that generated name; per-Edge overrides are rejected. The Portal resolves to its
region's entrance, **not a private Edge address**. HAProxy sends new browser
connections to healthy Edges in that Region. Register the three
generated callback URLs with your identity provider and trust the browser CA.

Before browser authentication, activate `ceremony-recovery-v1` only after every
required CP/Edge reports the supported capability and a current deployment epoch.
Sealed ceremony recovery, the shared binding key, and the CP's atomic result store
allow another healthy Edge to finish a pending login. Backend health alone does
not prove this readiness. Losing a Region's entire entrance still loses that
browser origin: agents can request authentication through another authorized
Region, but an already open callback is not silently moved to another origin.
The installer emits `DSSE_ENTRANCE_PORTAL_ORIGINS` as the allowlist of endpoint
and Connector transport SNI names. In this three-Region profile, a receiving
Edge accepts only a listed SNI and starts a **new** sign-in at its own Region's
Portal. With the normal DNS/EIP mapping, an agent selecting entrance A reaches
CP/HAProxy A, is processed by Edge A-1 or A-2, and selects Portal A. If an
approved transport SNI is carried to a different physical entrance during
failover, that entrance's Edge selects its own Region's Portal. An SNI name
alone does not establish which physical CP received the connection; inspect
both ingress and backend. Unknown ingress SNI fails visibly rather than
choosing the Edge-local origin.
Generic aliases follow the plan's `shared_entry_machine` (founding CP by default);
DNS must match that host. See the [installation and staged upgrade guide](releases/0.4.0/install-multi-edge.md).

Each Edge needs a browser-trusted SAN pair covering its own Region's Portal
name. The validated three-Region deployment used separate regional leaves
whose SANs covered only their respective Portal names. The signed endpoint
profile still contains all three origins as failover candidates; it does not
make an Edge serve every Portal. Cross-Region DNS takeover of an existing
Portal hostname is not part of this topology. Another authorized Region can
serve a **new** authentication request through its own Portal origin.
Verify it locally with `dsse-install -verify-portal-certificate -dir <deployment-directory>`. Origin
selection uses an explicit allowlist, with one fixed OIDC redirect URI and recovery
binding per origin. Multi-Edge authentication starts require a verified endpoint request and
active ceremony recovery; anonymous process-local starts are refused.

An L4 pool cannot choose a tenant-specific backend set inside encrypted TLS.
Endpoints and Connectors select only authorized Regions, and an out-of-boundary
Edge still refuses a restricted tenant before data dispatch or sign-in. Never
silently widen residency. The API and Console
require explicit acknowledgment before saving a new narrower boundary and warn
about existing conflicts; acknowledgment does not remove enforcement.

Internet egress uses an Edge in the selected entrance's Region. Include every
authorized failover Region's effective Edge/NAT sources in SaaS allowlists,
consider location-based access checks, and measure latency after Region failover.

The entrance passes TLS through. It uses `leastconn` for new mux TCP connections;
it cannot independently distribute the flows inside an existing mux connection.
The profile requires mux-only steering to avoid routing legacy session follow-up
requests to another Edge. Health checks exclude unhealthy Edge backends from new
connections. Existing connections do not migrate between Edge processes.

Management writes go to the elected CP; Console readiness follows the colocated
CP's leadership. The entrance checks direct private CP/Console listeners with
certificate verification, never another entrance's public port as a leader probe.

## Private network requirements

Apply firewall restrictions before exposing services. The generated environment
and Compose files are authoritative for ports and bind addresses.

| Source and destination | TCP ports |
|---|---|
| Endpoints and Connectors to a regional entrance | 443 |
| Authorized administrators to management SNI names | 443 |
| Each entrance to dedicated Edges in its own Region | 8443 (traffic), 9443 (health/admin) |
| Deployment nodes to remote entrances | 443 for authority and mesh paths |
| CP nodes to each CP's private management/data/Console listeners | 19543, 19545, 19544 |
| State-bearing CP nodes to one another | Generated etcd, Patroni and database ports |
| CP nodes to external archive, if configured | TLS to the operator-managed S3 endpoint; no S3 rule in local-only mode |
| Edge peers | Generated mesh listeners; restrict access to the deployment |

Never expose state-service or private management listeners to the Internet. Each
Edge trusts PROXY metadata only from its declared regional entrance address.
Additional NAT/proxies need an explicit, verified source-address design.

Private management currently requires IPv4. That does not disable IPv6 client
traffic or provide IPv6 egress automatically. For IPv6 endpoints, follow the
[dual-stack preparation](deployment.md#choose-ipv4-only-or-dual-stack-before-enrolling-devices)
and verify working IPv6 Internet egress from **every** Edge before enrollment.

## Acceptance before use

Test allowed and denied traffic, tenant isolation, certificate validation and
revocation, and browser login through every region. Measure actual mux distribution
and successful traffic per Edge; connection counts alone do not prove equal CPU or
bandwidth usage.

Then stop an entrance host alone while its Region's Edges stay healthy, and issue
fresh browser authentication from both OSes via every surviving entrance.
Confirm that the outer transport SNI is allowlisted and that the **new** Portal
origin matches the processing Edge's Region. Confirm the DNS/EIP, physical
CP/HAProxy host and processing Edge together: an SNI name alone does not prove
which Region's entrance received the TCP connection. An approved SNI may retain
its old name after failover; this does not make the old Portal the new sign-in
origin. Each physical entrance uses only its own Region's Edge pool.
An already-open callback on the stopped Portal origin does not migrate; require
a fresh request through the newly selected Region.
Also stop individual Edges, all Edges in one region, each regional entrance, and
an entire region. Record failures, selected destinations, and automatic recovery
on agents and Connectors. Also test CP/database leadership changes, a one-versus-two
partition, refusal of minority writes, and rejoining. Verify certificate renewal,
rolling replacement, and isolated backup restoration. Keep failure and missing-data
records. Local configuration and HAProxy tests do not replace these checks.
