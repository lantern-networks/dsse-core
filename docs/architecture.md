# Architecture

`dsse-core` is a Secure Service Edge (SSE / ZTNA) data plane. Endpoint agents steer supported,
selected traffic to an **Edge**, which authenticates the device, evaluates policy, and
forwards or denies; selected TLS traffic is decrypted for inspection. A **control plane**
authors and distributes enforcement configuration. **Connectors** reach private applications
from inside a customer site. Deployment transport and management links use TLS or mTLS;
the application protocol on an origin or connector-to-application connection is separate.

Steering exclusions, OS limitations, VM traffic, and fail-open configuration can leave
traffic outside the Edge. Review the platform guides and actual device profile; installing
an agent does not establish that every packet traverses this path.

[PKI structure and lifecycle](pki.md) describes the separate deployment and customer
authorities, current key custody, automatic renewal, and operator-managed replacement.
For configuration and current enforcement limits, see [IdP integration](idp.md),
[Egress policy](egress-policy.md), and [East-West policy and step-up](east-west-policy.md).

## One binary, two roles

`dsse-edge` is the Edge. Told so with `-control-plane`, the same binary is the control plane. They differ in
what they hold, and each node reports that about itself at `GET /healthz` (`role`, `holds_database`).

```
   device agent                         Edge (dsse-edge)                control plane (dsse-edge -control-plane)
  (macOS NE / Win WFP)                                                  authors what the Edges enforce
  +--------------+   (T) mTLS transport  +------------------------+  pull  +------------------------+
  | steer        | --------------------> | /steer/agent-policy    | <----- | /admin/config-bundle   |
  | selected     |   /steer/dns-query    | /steer/dns-query (DNS) |        | /admin/policies        |
  | traffic      |   runtime-copy/tunnel | runtime-copy/tunnel    |        | the enrolled inventory |
  +--------------+                       |   |                    |        | the one-time decisions |
                                         |   v  Matches?          |        +-----------+------------+
                                         |  intercept -> decrypt -> policy -> origin   |
                                         |  bypass    -> raw-forward --------> origin  | owns
                                         |                        |                    v
                                         | /connectors/{id}/tunnel| <-- connector    Postgres
                                         +------------------------+     publishes private apps
                                                   | reports
                                                   v
                                             the control plane
```

An Edge holds no database. Its configuration arrives in a signed bundle it pulls; its durable shared state
lives on the control plane; the one-time decisions — may this enrolment token be spent, has this identity
already enrolled — are **asked** of the control plane rather than answered from this node's own memory. An
Edge answering them alone means "once per Edge" rather than once, which is a second issuer handing out a
certificate for a name already in use.

An Edge also **refuses** to author what the bundle carries. A write accepted there diverges from the fleet and
does not correct itself, because an Edge's own divergence moves nobody's generation and nothing re-applies
until something unrelated happens to.

## What travels in the bundle

Policies and per-organization enforcement configuration, the enrolled inventory, authored rules and the asset
catalogue, the Site catalogue a connector's bootstrap secret is checked against, the device-CA registry, the
inspection posture, the transport trust distribution, and the class-1 region map.

A section only carries if three things are true: it **exists** on the wire, it moves the bundle's aggregate
**generation** — or it is published in every bundle and applied by nobody — and "there are none" is
**sayable**, or the last removal never propagates. These rules also apply to removal and empty-state updates.

Absence and emptiness mean different things per object, and the difference is the blast radius of being
wrong. An empty Site catalogue clears, because it refuses new connectors while registered ones keep working.
An empty device-CA registry removes nothing, because an empty registry refuses every device of every
organization. An empty region map clears, because a map still naming a region the deployment no longer has
sends devices to an address nobody serves.

## The decision path

A steered flow reaches the edge over the (T) mTLS transport. For port 443 the edge decides
**intercept** (decrypt) or **bypass** (raw-forward) — see [interception](#interception). On an
intercepted flow, each request is evaluated by `decision.Evaluator` against `policy.Store` (default-deny;
allow / deny / decrypt / step-up), tenant-restriction headers are applied (`swghttprewrite`), and the
request is forwarded to the origin. A new customer has an explicit broad Allow + Inspect
rule, and East-West starts in Observe; evaluator default-deny does not override those
settings. Decisions use the configured logging and delivery paths; see
[Audit logs and data handling](audit-and-data.md) for persistence and coverage limits.

Key packages: `decision` (evaluation), `policy` (the policy store + tenant config), `model` (the wire
types), `swg` / `swghttprewrite` / `inspection` (SWG + header rewrite + inspection events).

## Transport & device identity

The endpoint reaches the edge over a TLS transport that pins the edge CA and presents a device client
certificate (mTLS). The edge validates the device against `tenantca` (tenant CA chain) and
`enrolledinventory` (admission allowlist), and binds the verified device identity into the decision. The
agent also pulls a signed steer-exclusion policy from `/steer/agent-policy` (`agentpolicy`, Ed25519) and
resolves DNS over the tunnel (`dnsresolver`, with `dnsech` ECH-strip so the inner SNI is visible).

## Interception

`interception.Engine` terminates the client's TLS with a per-SNI leaf signed by an interception CA the
endpoints trust — four words that are the hardest part of putting a device on a deployment, and are worked
through in [macos-agent.md](macos-agent.md#the-part-that-decides-whether-it-works-trust) — then serves the decrypted HTTP (HTTP/2 or HTTP/1.1) to a `FlowHandler` that enforces
policy and reverse-proxies to the real origin. `Matches()` routes intercept-vs-bypass (port 443; bypass
hosts win). A host that repeatedly rejects the leaf is **proposed** as a bypass candidate
(`policycandidate`) for an admin to approve and materialize — detection never auto-bypasses.

## Egress (the upstream leg of interception)

### Standard behavior: Go HTTP/TLS

The standard build and generated deployment use **Go's HTTP and TLS implementations**
to connect from the Edge to the origin. This is the configuration selected for the
Experimental release; it does not require an egress broker or native browser libraries.

After terminating the client's TLS, the Edge evaluates the decrypted request against
policy and applies the configured SaaS tenant-restriction and DLP controls. An allowed
request is forwarded over a separate upstream connection with the origin's certificate
verified. An access-policy denial prevents forwarding. DLP can instead interrupt an
upload during streaming, after earlier cleared bytes have reached the destination; see
[DLP](dlp.md) for that distinction. The response returns through the Edge to
the client. The client's TLS session and the upstream TLS session are separate.

The upstream connection has Go's TLS/HTTP fingerprint. Compatibility with a particular
site's bot protection must be tested in the intended deployment. The egress guard also
checks destinations and actual connected addresses against `swg`'s block list to prevent
the proxy from becoming an SSRF path.

### Optional browser-compatible transport

The [egress broker](../egress-broker/README.md) can replace the upstream transport with
curl-impersonate (BoringSSL and a browser-compatible HTTP/2 profile). Policy decisions
remain at the Edge. **This option is disabled by default** (`-swg-egress-browser-mimic=false`)
and is not included in the generated standard deployment. Enabling the broker mode
requires a separately configured broker and `EGRESS_BROKER_URL`; failures in that enabled
path do not silently fall back to Go. The broker guide covers integration, native build
requirements, and the separate embedded-engine build. Browser compatibility still needs testing.

## Config distribution (control plane)

The control plane is the config authority: administrators author through its admin API, and it serves the
current bundle (`configbundle`). An Edge pulls it and applies any newer generation, rebuilding the evaluator
atomically so changes hot-apply with no restart.

The generation is an aggregate across every store that contributes a section, and it travels with an
**epoch**. The two are only comparable together: a control plane recomputes its generation from its stores on
restart, so the number can come back lower than what it last published, and comparing numbers alone reports a
fleet as behind when it is looking at a control plane that restarted.

A bundle is signed with the shared agent-policy key so a pulling Edge can reject a tampered or forged
configuration; a party without the signing key cannot forge a bundle. A control plane that holds the
signing key remains part of the trusted authority; its compromise is outside that protection.

## Private apps (connector)

`dsse-connector` registers with the edge and dials an outbound mTLS `tunnel` — no inbound firewall
holes. The edge proxies a steered flow for a published app through that tunnel; the connector dials the
real private app and streams bytes back. Registration/heartbeat live in `connector`.

## Endpoint agents

Under [`clients/`](../clients): the macOS `NETransparentProxy` system extension (Swift) and the Windows
WFP kernel callout driver + Go steering agent. They capture endpoint flows and carry them to the edge
over the (T) transport described above. See [macOS](macos-agent.md) and [Windows](windows-agent.md) for installation.

## Security model

See [SECURITY.md](../SECURITY.md) and [Threat model](threat-model.md). Edge/control-plane
listeners require TLS, and inspection signing keys require protection as interception
authority. Detection proposes bypass candidates for review rather than enabling them
automatically. DLP findings omit matched values, but audit metadata can still identify
users and destinations; review it before sharing. These controls do not establish complete
traffic coverage, independently audited isolation, or production readiness.
