# Deployment

This guide installs a DSSE lab from the public repository, starts its services, creates
an administrator, and checks the running deployment. Continue with [First use](after-verify.md)
to configure an organization and connect an endpoint. **This release is experimental.**

`dsse-install` generates the certificates, configuration, start scripts, and Compose files.
Its `-plan ... -order` output is the command reference for your topology. Run each step
on the machine it names; the output is instructions, not a shell script to execute wholesale.

## 1. Prepare the machines

| Shape | Machines | Availability |
|---|---|---|
| Single-machine lab | One region with one control plane and one Edge | No host redundancy; loss of the machine stops the deployment |
| Three-region lab | Three regions, one node each; each node holds a control plane, Edge, and state | Designed to retain quorum after one region is lost; requires independent failure domains and working peer links |

Three region IDs on one host do not provide regional fault tolerance. Certificate renewal,
failover, and recovery must also be tested on the deployed build; the topology alone does
not establish their reliability.

The control plane owns the shared configuration database. An Edge that receives
configuration through `-config-source-url` or `-config-source-endpoints` must use
node-local configuration stores and must not also set `-postgres-dsn`. The process
refuses this combination before connecting to the database, because applying an
older received bundle could overwrite newer control-plane configuration. This
also applies when the same process is marked `-control-plane` or has explicit
store overrides. The generated installer configuration already separates these roles.

Before starting, prepare:

- Linux hosts with Docker Engine and the Compose v2 plugin, persistent storage, and
  permission to run Docker and create the deployment directories. The examples use `/opt/dsse`.
- A build environment with Git and a patched Go toolchain; use Go 1.27.1 for this release
  as described in [Building](building.md). All nodes must run the same chosen revision.
- Synchronized clocks on the servers and endpoints. Certificate validity and MFA depend on time.
- Stable host addresses and DNS records that resolve from the hosts, containers,
  administrator's computer, connectors, and endpoint devices.
- Firewall access as described under [Network access](#network-access), and registry
  access for the generated stack's third-party images (or preloaded copies).
- A package-signing identity and signed Windows/macOS installers if endpoints will join.
  These are separate from the deployment's TLS authorities; see [Building](building.md).

### Choose IPv4-only or dual-stack before enrolling devices

Choose one mode for **every Edge region** and check it before installing agents. This
procedure supports dual-stack or IPv4-only deployments; it does not establish an
IPv6-only installation. The generated Docker network has an IPv6 ULA, but that
alone does **not** give an Edge
outbound IPv6 Internet access. Endpoint capture includes IPv6 TCP. An IPv4-only Edge
reports that it cannot carry IPv6 and the Windows agent closes those captured flows;
some browsers do not recover by trying IPv4, even when the site has an A record.
Therefore an IPv4-only deployment is not an automatic, transparent fallback for a
dual-stack endpoint.

| Mode | Prepare before installing endpoints | Acceptance check |
|---|---|---|
| Dual-stack (use when endpoints have IPv6) | Give every Edge host working outbound IPv4 and a global IPv6 address, a `::/0` route, and firewall egress. Carry IPv6 from its container through host forwarding/NAT as needed; the container may use ULA. Keep regional transport names reachable by the address families actually used by endpoints; they need not have AAAA records merely because Edge egress is dual-stack. | Every Edge's `/healthz` reports `egress_address_family.ipv4=true` and `ipv6=true`; `dsse-install -verify` carries its IPv6-only test flow. Then test a real IPv6-only destination and a dual-stack page with an enrolled endpoint and TLS verification. |
| IPv4-only (step back when outbound IPv6 cannot be supplied) | Give every Edge working outbound IPv4. Before enabling DSSE on a device, use the [Windows](windows-agent.md#ipv4-only-deployment) or [macOS](macos-agent.md#ipv4-only-deployment) IPv4-only endpoint procedure. Keep transport/recovery DNS and peer addresses reachable over IPv4. | Every Edge reports `ipv4=true`, `ipv6=false`. The verifier's IPv6-only destination is explicitly unavailable; it is **not** an IPv6 pass. With the agent active, verify ordinary dual-stack sites in the actual browser, allowed HTTPS, denied traffic, and audit. |

For a dual-stack AWS VPC, associate IPv6 ranges with the VPC and each subnet, assign
IPv6 to each Edge instance, route `::/0` to the Internet gateway for a public subnet
or an egress-only Internet gateway for a private subnet, and allow required IPv6
**outbound** traffic in security groups and any custom network ACL. Do not add public
IPv6 inbound rules merely to enable egress. Check the host **and Edge container** for
an actual outbound IPv6 connection; a global address or Docker ULA alone is not a
reachability test. See [AWS's IPv6 VPC procedure](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-migrate-ipv6-add.html).

After starting each region, first confirm outbound IPv4 and IPv6 on its host with
`curl -4 --fail https://example.com/` and `curl -6 --fail https://ipv6.google.com/`.
Then run the printed fleet `dsse-install -verify` command in step 7: it checks each
Edge's measured family and sends a real flow through DSSE to an IPv6-only origin.
The host probes alone cannot establish container or DSSE reachability. If any
Edge reports `ipv6=false` or the DSSE flow fails, fix that region's address,
route, forwarding/NAT, or egress firewall before enrolling devices.

Do not publish an AAAA record for a regional front door until that address accepts
the intended TLS connection. Do not turn on fail-open, exempt IPv6 from steering, or
disable certificate checks to make a page load. If endpoint and Edge address families
do not match, correct the network mode and repeat the endpoint check before counting
the installation as successful.

Disk and memory needs depend on traffic, audit retention, and database workload. No
production sizing is claimed here. Monitor disk use for Postgres, ClickHouse, MinIO, and
Edge audit spools during the lab; do not treat an empty-stack startup as a capacity test.

## 2. Clone and build

On the founding node, or a build host targeting that node's architecture:

```sh
git clone https://github.com/lantern-networks/dsse-core.git
cd dsse-core
export GOTOOLCHAIN=go1.27.1
mkdir -p bin
go build -o bin/dsse-install ./cmd/dsse-install
go build -o bin/dsse-profileverify ./cmd/dsse-profileverify
export PATH="$PWD/bin:$PATH"
```

Use the revision associated with the release you are evaluating. Build **both** service
images and load them on every node, following [Building](building.md#build-the-service-images).
Keep `dsse-install` on `PATH` when changing directories. If a separate build host is used,
copy the matching installer binary and the chosen plan to the founding node as well.

## 3. Write a plan

Copy one example, then edit it for your environment:

```sh
cp docs/plans/three-regions.json plan.json
# For a single-machine lab, use docs/plans/single-region.json instead.
```

The examples are [three regions](plans/three-regions.json) and
[one region](plans/single-region.json). **Their names, addresses, and publisher are placeholders.**
Replace them before minting:

| Field | Value to supply |
|---|---|
| `deployment` | DNS suffix under your control; `example.test` is only a private test example |
| `agent_publisher` | Identity expected by the endpoint package verifier, matching your signed packages; not a display name or the example placeholder |
| `regions[].id` | Stable region identifier |
| `founding` | `true` on exactly one region, where authorities are first minted |
| `holds_state` | `true` on each of the three voting regions |
| `machines[].name` | Unique machine name |
| `holds` | `["control-plane", "edges"]` for each node in these examples |
| `addresses` | Address actually assigned to that host; Compose binds to it |
| `reachable` | Name other machines use to reach that host, also used for TLS |
| `reachable_address` | Explicit IP where peers reach that host; required for cross-region routing and may differ from its local bind address behind NAT |
| `mesh` | `true` to relay private-application traffic between regions; does not grant policy access |

Behind NAT, the bind address and the DNS-visible address may differ. Do not put an
unassigned public/NAT address in `addresses`; provide working routing for `reachable` and `reachable_address`.
For macOS, the publisher is the Apple Team ID used for the package. Check the generated
profile against the intended platform's package before issuing it to a device.

Use an absolute plan path so later directory changes cannot break the commands:

```sh
export DSSE_PLAN="$PWD/plan.json"
export DSSE_DIR=/opt/dsse/region-a
umask 077
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -order > install-order.txt
```

Set `DSSE_DIR` to the founding region's directory if you changed the example region name.
Review the order and assign the required host permissions before executing it.

### Reapply a plan to an existing machine

To refresh an existing machine's generated configuration, specify that machine:

```sh
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -machine node-b
```

A carried node does not hold the consensus-store CA private key. Reapplying its
plan reuses its existing member certificate and key only when the pair is valid,
trusted by its store CA, and matches the planned member name and peer address.
An Edge-only machine does not require store-member material. If a state-bearing
node needs a new certificate, re-pack that machine on the issuing host and
replace its material through your maintenance procedure; do not copy the CA
private key onto it. A certificate preflight failure leaves `deployment.env`
unchanged. This is not a transaction across every generated file, and generation
does not restart running services.

## 4. Mint once and configure name resolution

Run the first printed command **on the founding node**, using your operator organization name:

```sh
dsse-install -plan "$DSSE_PLAN" -dir "$DSSE_DIR" -organization "Example Operator"
```

`-organization` sets the organization name in the deployment's initial certificates.
It does not create a customer or set its Console display name. Create customers later
in the Console. Record the printed names and trust-anchor fingerprint. Protect the
whole generated directory: it contains credentials and private keys. Keep an encrypted
backup of the founding authority material; do not commit it or copy it into an image.

Minting outputs the names the deployment needs. Configure all of them, including:

- `node-a.<deployment>` and each other machine's `reachable` name;
- `agents.<region>.<deployment>`, `admin.<region>.<deployment>`,
  `authority.<region>.<deployment>`, and `console.<region>.<deployment>`;
- the generated per-node admin names and deployment-wide agent/recovery names.

Use the generated list rather than constructing an incomplete DNS zone from these examples.
Each regional name must reach that region's front door. Test resolution **inside the
containers as well as on the hosts**. For a one-machine lab without container DNS, the
generated `deployment.env` has four `DSSE_HOST_ALIAS_1` through `DSSE_HOST_ALIAS_4` slots:

```sh
DSSE_HOST_ALIAS_1=node-a.example.test:host-gateway
DSSE_HOST_ALIAS_2=agents.region-a.example.test:host-gateway
DSSE_HOST_ALIAS_3=admin.region-a.example.test:host-gateway
DSSE_HOST_ALIAS_4=authority.region-a.example.test:host-gateway
```

Use these only when that gateway can reach the host's bound ports. They do not configure
the administrator's or endpoint's resolver, and cannot replace cross-node DNS in a three-region lab.

Check `DSSE_IMAGE` and `DSSE_CONSOLE_IMAGE` in `deployment.env` and resolve any
[container subnet conflicts](building.md#container-network-conflicts) before starting.

## 5. Start the founding region and create an administrator

Follow the next commands in `install-order.txt`. Starting the founding region uses:

```sh
cd "$DSSE_DIR"
docker compose -p dsse --env-file deployment.env up -d
docker compose -p dsse --env-file deployment.env ps -a
```

Some initialization services exit successfully after their work; long-running services
must remain running and become healthy. Inspect failures with:

```sh
docker compose -p dsse --env-file deployment.env logs --tail=100
```

Wait for the control plane to answer over verified TLS. For the unmodified example names:

```sh
curl --fail --show-error --cacert "$DSSE_DIR/deployment-anchor.pem" \
  https://admin.region-a.example.test/healthz
```

Retry while services initialize. If it continues to fail, check DNS, clock, certificates,
and service logs. The installer's printed readiness hint may use `curl -k`; use the
`--cacert` form above so a successful probe also validates the expected deployment.

Then run the generated `-bootstrap-admin` command with your email address. On Bash or zsh:

```sh
umask 077
set -o pipefail
dsse-install -bootstrap-admin -dir "$DSSE_DIR" \
  -control-plane https://admin.region-a.example.test \
  -admin-email admin@example.test 2>&1 | tee "$DSSE_DIR/admin-credentials.txt"
```

Replace the example URL and email. Check the command's exit status before proceeding.
The output contains the generated password, **TOTP second-factor secret**, recovery codes,
and named API token. Store them securely; initialize an authenticator with the second-factor
secret. Never paste this file into an issue or attach it to diagnostics.

Run the printed recreation step for **both** the control plane and the Edge:

```sh
docker compose -p dsse --env-file deployment.env up -d --no-deps --force-recreate \
  dsse-control-plane-a dsse-edge-a
```

This closes the running break-glass session and loads the fleet credential. Wait for
services to become ready again before joining regions or verifying.

## 6. Join the other two regions

Skip this section for the single-machine plan. Execute the remaining per-machine steps
from `install-order.txt` in order. The installer prints the exact membership commands.

1. On the founding node, add the next state member as a learner and generate its archive
   with `-plan ... -carry <machine>.tar.gz -machine <machine>`.
2. Copy that archive to the named host. Adapt the printed `scp` destination to your SSH
   user and key. Both service images must already be loaded there.
3. On that host, extract into the printed directory and start its generated Compose project.
4. Once the learner has caught up, run the printed promotion command on the founding node.
   A refusal because it is still catching up means wait and retry that promotion.
5. Repeat for the third region. Confirm three voting members in three failure domains.

**Do not run a fresh mint on the other nodes and do not use `-force`.** They must share
the founding deployment's trust. `-carry` excludes `authority/`; certificate-issuing
operations remain on the founding machine. The archive still contains runtime private
keys and fleet credentials: transfer it securely and remove transit copies after extraction.
Two voting members cannot tolerate the loss of either member; finish the third region.

## 7. Verify the whole fleet

Run the final `dsse-install -verify` command printed by `-order`, using the **named API
token** from bootstrap. Keep all entries in `-edge`, `-edge-admin`, and
`-control-plane-peers`; a check through one load-balanced name cannot observe every node.

`NAME@ADDRESS` in these arguments preserves the TLS name while selecting the dial address.
It does not configure DNS for device-style checks. Run verification where all generated
names resolve normally.

Success requires **zero failed checks** and review of every **could not be answered** or
`n/a` result. Check counts vary with the installed resources. A fresh deployment has no
customer organization, so device enrolment cannot yet be proved. A single-machine plan
also reports its lack of redundancy as the selected shape; that is not a failover test.
For IPv4-only mode, record the verifier's IPv6-only flow as an expected limitation,
not a successful IPv6 test. For dual-stack mode, that flow and every Edge's measured
IPv6 egress must succeed before enrolling devices.

After these infrastructure checks, follow [First use](after-verify.md). Installation is
complete only after a customer endpoint has enrolled, passed its verifier, and exercised
both allowed and denied traffic. Keep default-TTL rotation and outage testing separate
from this startup check.

## Certificates

`deployment-anchor.pem` authenticates the deployment's TLS services. Compare its SHA-256
fingerprint with the securely obtained minting record **before trusting it**:

```sh
openssl x509 -in deployment-anchor.pem -noout -fingerprint -sha256
```

On the administrator's computer, import that verified certificate into the trust store
used by the browser. Examples (administrator privileges required):

```sh
# macOS
sudo security add-trusted-cert -d -r trustRoot -p ssl \
  -k /Library/Keychains/System.keychain deployment-anchor.pem

# Debian/Ubuntu
sudo cp deployment-anchor.pem /usr/local/share/ca-certificates/dsse-deployment.crt
sudo update-ca-certificates
```

```powershell
# Windows: first compare the SHA-256 fingerprint using the command above.
Import-Certificate -FilePath deployment-anchor.pem -CertStoreLocation Cert:\LocalMachine\Root
```

A Windows certificate object's `Thumbprint` is not the SHA-256 fingerprint used above.
Tools with their own CA bundle may need `--cacert deployment-anchor.pem` even when the
browser trusts it. Never infer trust from an issuer name alone.

The customer organization's transport, device identity, and interception authorities
are configured separately under [Organizations](organizations.md). Do not distribute
private CA keys to endpoints.

## Break-glass, and closing it

Before bootstrap, generated scripts arm the initial owner credential while
`runtime/admin-bootstrapped` is absent. Bootstrap creates the named administrator and
fleet credential and writes that marker. The recreation step makes the running processes
load the new state.

For lost administrator credentials, the recovery path requires access to the founding
control plane's deployment directory: move the marker aside, restart the control plane,
and run `-bootstrap-admin` to obtain replacement credentials. Then recreate the affected
services and verify again. This is an owner-level recovery operation; protect write access
to the deployment directory accordingly. Do not use re-minting as account recovery.

## Network access

The regional front door routes TLS by SNI on TCP 443 and passes client certificates
through to the Edge. Use the generated hostnames, not bare IP URLs.

| Connection | Access required |
|---|---|
| Endpoint/connector to regional front door | TCP 443 |
| Administrator to Console and admin names | TCP 443, restricted to administrator networks |
| Nodes to other regional doors | TCP 443 for authority and mesh paths |
| Peer nodes to published Edge ports | Generated agent/admin ports (defaults 8443 / 19443), restricted to deployment peers and verification hosts |
| State-bearing nodes to one another | Generated etcd client/peer, Patroni, database, and archive ports, restricted to deployment peers |

Typical state ports include 12379/12390 (etcd), 18008 (Patroni), 15432 (database), and
19000 (archive). The generated `deployment.env` and Compose file are authoritative; inspect
them for every host rather than opening a range to the Internet. Direct Edge ports are
published for peer communication and verification; an unadvertised port still needs a firewall.

## State, stopping, and restarting

The control plane owns Postgres, ClickHouse, and MinIO. Edges retain local audit spools
and ship records to the control plane. Include all of these in storage and backup planning.

In a shared PostgreSQL deployment, east-west and policy-candidate observation
reports are committed with their receipt in the control-plane store. Receipts retain the most recent 4,096 sequence positions
per shipping identity, reporter process and stream, across all of that reporter's
tenants. Reports may arrive out of order within that window; duplicates there do
not add counts again. This is a sequence budget, not a duration or a delivery
guarantee derived from the sender queue size.

A report at or below the persisted retired prefix receives HTTP 422, whether it
was previously applied or never arrived. It is neither acknowledged as applied nor
counted again. The observation shipper appends refused bytes to its `.refused` spool once other
records demonstrate successful delivery, and reports the refusal in logs/health.
That refused file is append-only and is not bounded by the CP receipt window;
include it in disk and retention management. Spool writes are best effort, so keep
the original local JSONL available when investigating delivery failures.
Investigate the original local JSONL and CP counts before reconciling a very late
report; changing its reporter or sequence can double counts. A channel-wide outage
continues retrying until delivery can make progress. Queue overflow and hook drops
still require attention to the local JSONL and delivery health.

Rows carrying observation receipts now use `eastwest_observations.v4` and
`policy_candidates.v4`. New readers accept the original tenant-map shape and v2/v3
receipts; the next accepted report bounds that reporter's retained gaps. Older
readers reject v4: upgrade all CP readers/writers together before allowing writes,
and restore a compatible backup if rolling back. Do not rename the row version to
force an older reader to accept it. Inactive reporters still expire after 30 days
when another report triggers pruning; this is not indefinite deduplication or a
bound on the total number of reporter identities.

A backup is not proved until it can be restored with its matching authority material.

Audit ingestion authenticates each Edge with its client identity and authorizes tenant
records and device enrolment reports through `audit-ingest-authority.json`. Check the generated mappings when adding
a customer; an Edge may enforce its traffic while its audit records are refused by the
control plane. Verify delivery and receipt for that customer, not only the operator tenant.
Enrolment reports remain in the Edge outbox during storage failures or a leader change.
Authorization failures also require correcting the identity mapping before delivery can resume.

From the generated directory, stop a single-machine lab without removing its volumes:

```sh
docker compose -p dsse --env-file deployment.env stop
# Start it again:
docker compose -p dsse --env-file deployment.env up -d
```

Joining regions use the project name printed for them (for example `dsse-region-b`).
For a three-region deployment, restart one region at a time and restore quorum/health
before proceeding. Do not use `down -v` to restart: it removes persistent volumes.

To retire a device, block or remove it in the Console, then uninstall its agent following
the platform guide. Removing a package does not revoke the enrolled identity.

Enrolment reports also require the Edge-to-tenant mappings in `audit-ingest-authority.json`. Verify each served customer mapping before upgrading: an unreported device may lose admission on a later configuration refresh.
