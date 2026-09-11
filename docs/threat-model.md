# Threat model

This is the threat model for the `dsse-core` data plane. It is intentionally concrete about what the
code defends, what it assumes, and what is out of scope — a security product should be auditable on
exactly these points.

## Assets and trust boundaries

- **Traffic confidentiality/integrity policy** — which flows are decrypted, inspected, allowed, denied,
  or stepped up. The control plane authors policy; the **Edge** enforces it for traffic it receives.
- **Device identity** — the (T) transport client certificate; the edge trusts the tenant CA chain and an
  enrolled-inventory allowlist, not endpoint-claimed identity.
- **Inspection authority keys** — root and issuing keys authorize subordinate authorities;
  the Edge inspection key signs per-host leaves. A compromised key affects the trust scope
  beneath it. See [PKI](pki.md) for shared versus customer-specific authorities and custody.
- **The agent-policy signing key** — signs the steer-exclusion policy the endpoint applies (Ed25519);
  the endpoint pins the public key.

Trust boundary: the endpoint is **assumed potentially compromised**. Enforcement therefore happens at
the edge (a separate trust domain), and endpoint-supplied identity fields do not replace transport identity checks. This
boundary does not ensure all endpoint traffic reaches the Edge: exclusions, platform
limitations, VM traffic, and fail-open settings need separate coverage tests. It also
does not remove the [current IdP and grant-scope limitations](idp.md).

## Threats and how the data plane addresses them

| Threat | Mitigation in dsse-core |
|--------|-------------------------|
| **Endpoint claims a false identity** | Device identity comes from the verified mTLS transport cert (`tenantca` chain + `enrolledinventory` admission), not from client-supplied fields. |
| **Plaintext downgrade / accidental cleartext** | The reference edge/control-plane **refuse to start without TLS** — there is no plaintext serving path. |
| **Interception CA misuse** | Protect every root, issuing, and Edge inspection key. Short-lived per-host leaves do not neutralize CA-key compromise; scope depends on the authority and the clients trusting it. See [PKI](pki.md). |
| **QUIC / HTTP3 escaping interception** | The default endpoint policy blocks UDP/443 for steered flows, and the Edge strips `Alt-Svc` on intercepted HTTP responses to favor the inspectable TCP/TLS path. Actual coverage depends on the applied profile and platform; this is not inspection of arbitrary UDP traffic. |
| **ECH hiding the destination** | The Edge DNS resolver strips ECH from answers it handles (`dnsech`). This does not establish control over cached answers or queries that do not pass through that resolver; verify the client's actual DNS and TLS path. |
| **Cert-pinning used to evade inspection** | A host that rejects the interception leaf is **proposed** as a bypass candidate (`policycandidate`) for admin review — detection never auto-bypasses, so an attacker cannot force themselves into the bypass set by failing handshakes. |
| **Default-allow gaps** | The general evaluator is default-deny, but a new customer has a broad explicit Allow + Inspect rule. East-West Observe permits traffic, Partial permits unmatched traffic, and Warn permits even in Full. Review [Egress](egress-policy.md) and [East-West](east-west-policy.md) before relying on denial. |
| **Stale config after a change / revocation** | Config hot-applies via control-plane pull (`configbundle`); the evaluator is rebuilt atomically. Revocation (`revocation`) and liveness (`liveness`) drive continuous re-evaluation. |
| **Inbound exposure of private apps** | Connectors dial **outbound** mTLS tunnels; there are no inbound firewall holes to the private network. |
| **Secret leakage via logs/observation** | DLP findings omit matched payload values, but user/device/account and destination metadata can remain identifying. Inspect actual logs, exports, and diagnostics before sharing; see [Audit and data](audit-and-data.md). |

## Assumptions

- The interception CA and agent-policy signing keys are provisioned and protected by the operator.
- The endpoint trusts the interception CA (e.g. via MDM) so leaves are accepted; the agent pins the
  edge transport CA and the agent-policy public key.
- The operator chooses strong admin tokens and protects the control-plane admin API.
- **Write access to a control-plane machine's deployment directory is owner-level access to the deployment.**
  The break-glass credential is closed by the presence of a file — `runtime/admin-bootstrapped` — beside a
  `deployment.env` that still holds `ADMIN_TOKEN`. Moving that file and restarting the control plane arms an
  owner credential again, and every act performed with it is attributed to a synthetic principal rather than
  to a person. This is deliberate: it is the only way back for an operator who has lost the first
  administrator's credentials, and it is stated here because a recovery path nobody names is a hole rather
  than a feature. Protect that directory as you protect the credentials themselves.

## Out of scope

- Operating-system / hardware compromise below the agent's enforcement floor (kernel rootkits, firmware).
  Raising that floor is a productization concern (tamper-resistance, MDM, signed drivers), not the data
  plane.
- Weak operator-chosen secrets and deployment misconfiguration.
- Denial of service and side-channel/timing attacks are not specifically hardened here.
- The code includes per-organization authorities and multi-region deployment support, but this
  experimental release does not claim independently audited tenant isolation or production HA.
  Validate isolation, certificate rotation, and failure recovery in the intended environment.

Found a gap or a vulnerability? Please report it privately — see [SECURITY.md](../SECURITY.md).
