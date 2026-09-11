# Release overview and known limitations

**Status: experimental. Documentation review date: 2026-09-11.**
This page describes the source tree's evaluation scope. It does not declare a release
tag, certify production readiness, or report a completed endurance run. Architecture,
defaults, APIs, and the limitations below may change; use the docs from the revision
you build. The [documentation index](README.md) provides the full reading path.

## Evaluation scope

| Area | Current documented path | What remains deployment-specific |
|---|---|---|
| Services | Self-hosted Linux / Docker Compose; control plane, Edge, and persistent state | Host sizing, network reachability, storage, recovery, and availability measurements |
| Topology | Single-machine lab or three-region lab | Independent failure domains and tested quorum/failover; three names on one host give no regional redundancy |
| Windows endpoint | Native agent installation and WebView2 OOB window | Actual OS/CPU, signed package and driver acceptance, WebView2 Runtime, IdP method |
| macOS endpoint | Signed/notarized package, Network Extension, resident user agent and WKWebView OOB | Actual OS/CPU, signing entitlements, approvals, steering, IdP method |
| Private resources | Outbound Connector tunnels and East-West policy | Each application's protocol, DNS, routing, and allowed/denied behavior |
| Internet access | Egress policy, TLS inspection, optional attached DLP | Client trust, application compatibility, bypasses, content coverage |

Windows and macOS are the endpoint installation paths covered by these guides. A Linux
service build or another binary in the tree is not a claim of equivalent packaged
endpoint support. See [Building](building.md), [Deployment](deployment.md),
[Windows](windows-agent.md), [macOS](macos-agent.md), and [Connectors](connector.md).
No tested minimum OS-version matrix or performance capacity is established by this page.

## Defaults to understand before enrolling devices

- A new customer's Internet Access policy explicitly allows and inspects broadly.
  Narrow it to your intended access. Connector access begins in **OBSERVE**.
- TLS inspection does not enable DLP by itself. Attach a DLP policy; Observe and Warn
  permit matching uploads. Uninspectable-file blocking is off by default.
- Standard upstream HTTP/TLS uses Go. Browser-faithful forwarding requires the optional
  egress broker and its separate integration.
- Generated PKI uses software-held key material. PKCS#11/HSM integration exists, but
  SoftHSM is not part of the default generated deployment.

These defaults are operational choices to review, not acceptance results. Details are in
[Egress policy](egress-policy.md), [DLP](dlp.md), and [PKI](pki.md).

## Known implementation limits

| Area | Limit to account for |
|---|---|
| PKI | Short-lived material has renewal paths, but node/service certificates do not have automatic reissue. Review key custody, expiry, and operator-managed rotation separately |
| IdP assurance | The shared broker's live-grant check does not enforce provider identity, AMR, age, or destination scope. OIDC request propagation does not provide all displayed assurance controls |
| Inspection bypass | Native TLS bypass host compilation does not preserve all source/service/risk constraints of a policy rule; it can exempt more traffic than the rule suggests |
| East-West enforcement | Observe permits traffic; Partial permits unmatched traffic. A Warn rule permits even in Full. Outbound source compilation does not handle shared IdP selectors equivalently to device selectors |
| OOB | Shared broker grants and the separate East-West challenge/grant API have different lifetimes and scope checks. Customer-tenant held-flow resume has a default-tenant lookup limitation; retry behavior must be tested |
| OOB UI | Windows launcher fallback and macOS embedded-window behavior differ. A browser login test does not prove passkey or MFA success inside either WebView |
| DLP | Limited methods, formats, and extraction; streaming interruption can follow delivery of earlier bytes. No finding is not proof of complete inspection |
| Audit and data | Finding writes can be best effort. Retention/hold settings do not cover all stores and copies; archive and object-lock behavior require operational verification |
| Administration | Role, home organization, customer delegation, and selected elevation checks are distinct. Host-level recovery remains a separate privileged authority |

Read the relevant guides before treating a configured field as an enforced security
condition: [IdP](idp.md), [Egress](egress-policy.md), [East-West and OOB](east-west-policy.md),
[DLP](dlp.md), [Audit and data](audit-and-data.md), [Administration](administration.md).
These are documented constraints, not a complete security audit or vulnerability inventory.

## Release evidence

The [Experimental release notes](https://github.com/lantern-networks/dsse-core/releases)
record the exact tag, source revision, downloadable packages, signatures, checksums,
validation scope, and implementation limits. Use those artifact identities when
reproducing a result; installation success alone does not establish recovery.

The three-region evaluation collected two overlapping observation windows of approximately
30 hours each, from September 9–10 and September 9–11, 2026 (UTC). Each window recorded
21,588 successful fresh TLS checks across two tenants and three regions, with five distinct
server certificates observed per region/tenant lane. The server-certificate lifetime was
12 hours. The windows overlap and are **not** a combined 60-hour test; they do not establish
60-day device-certificate endurance. Private-application probe failures associated with the
test HTTP server's execution timer are retained in the result record.

Service and endpoint fixes made after those windows receive separate regression and
short deployment checks. Their results must not be described as another completed
30-hour run. This includes Connector backend-refusal isolation, recovery on the main
agent port, recovery names in Console-issued profiles, and Windows identity selection
when changing organizations.

| Evidence | Where to check |
|---|---|
| Public source revision and tag | The release's tagged source and release notes |
| Downloaded package identity | Release asset checksums and the package's platform signature |
| Final source checks and service-image correspondence | Release notes and the source/artifact manifest |
| Endpoint installation and configuration | Platform guides and the verification scope in the release notes |
| Dependency inventory | Release SBOM; its stated scope excludes a full inventory of container OS packages, native code and drivers |
| Independent security audit, production capacity, or recovery guarantee | Not claimed |

For macOS, same-version Network Extension replacement can finish before the runtime is
available. Quit and reopen the application once, then verify active steering and inspected
traffic; see [macOS troubleshooting](macos-agent.md).

The [verification guide](verification.md) describes how to record topology, effective
lifetimes, start/end times, revisions, failures, and unrun cases. Keep deployment
credentials, private keys, and raw operational logs outside public release assets.

An accelerated certificate test does not substitute for a full run at normal lifetimes.
Successful startup or package installation does not establish enforcement, renewal,
failure recovery, or uninterrupted service. Recovery procedures require an actual restore
exercise before being treated as proven; [Operations](operations.md) currently covers
preparation rather than a certified restore runbook.

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
