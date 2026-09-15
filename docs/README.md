# Documentation

DSSE is an experimental, self-hosted Secure Service Edge (SSE / ZTNA) implementation.
These guides cover the source in this repository. Commands run from the repository root
unless a guide changes directory explicitly. Replace example names, addresses, and paths
with values from your deployment. Use the documentation from the revision you build.

## Choose a starting point

| Your task | Reading order |
|---|---|
| Review release scope, defaults, and unresolved evidence | [Release overview and known limitations](release-overview.md) |
| Understand the system and its trust boundaries | [Architecture](architecture.md), [Threat model](threat-model.md), [Security policy](../SECURITY.md) |
| Understand certificates, keys, and their renewal | [PKI structure and lifecycle](pki.md) |
| Evaluate a small API example | [Local API quickstart](getting-started.md); this does not install a fleet |
| Install a lab from source | [Building](building.md), [Deployment](deployment.md), [First use](after-verify.md) |
| Set up a customer and a device | [Organizations](organizations.md), [Windows](windows-agent.md) or [macOS](macos-agent.md) |
| Configure customer sign-in and assurance | [IdP integration](idp.md) |
| Control Internet traffic and content inspection | [Egress policy](egress-policy.md) |
| Configure upload detection and interruption | [DLP](dlp.md) |
| Manage administrators and customer delegation | [Administration](administration.md) |
| Register service accounts and review tool boundaries | [Service accounts](service-accounts.md), [Delegations and activity](delegations.md) |
| Locate audit evidence and manage its lifecycle | [Audit logs and data handling](audit-and-data.md) |
| Control internal access and out-of-band authentication | [East-West policy and step-up](east-west-policy.md) |
| Reach private applications | [Connectors](connector.md), then test both allowed and denied access |
| Operate or diagnose a deployment | [Operations](operations.md), [Troubleshooting](troubleshooting.md), [Verification](verification.md) |
| Publish endpoint updates | [Agent updates](agent-updates.md), [Operator tools](operator-tools.md) |
| Contribute a change | [Contributing](../CONTRIBUTING.md), [Building](building.md) |

The standard deployment uses Go HTTP/TLS for outbound inspected traffic. The optional
[egress broker](../egress-broker/README.md) has its own build and integration requirements.
[Dependency versions](dependency-versions.md) records the selected build inputs.
[SaaS tenant restriction](saas-tenant-restriction.md) covers account restrictions separately
from DLP and access policy.

## Terms used in the guides

| Term | Meaning |
|---|---|
| Deployment | Services and trust material managed together by an operator |
| Organization / tenant | A customer scope for devices, policy, authorities, and audit records; the guides use both names |
| Operator context | Deployment administration, initially `tenant_default`; customer devices must join a customer organization |
| Control plane | Configuration and shared-state authority, served by `dsse-edge -control-plane` |
| Edge | Authenticates device traffic, evaluates and enforces policy, and forwards traffic |
| Connector | A service inside a private network that opens outbound tunnels to the deployment |
| Install profile | Signed device configuration; it does not itself provide a unique device identity |
| Enrolment token | One-time authorization to obtain a device identity |
| Deployment anchor | Trust anchor for deployment services; distinct from the customer's inspection authority |
| Inspection authority | CA trusted by the client for certificates used in TLS inspection |

## Before relying on a result

The policy evaluator is default-deny, but a new organization's Internet Access rule
explicitly allows and inspects broadly. Connector access starts in **OBSERVE**. Review
these [initial settings](organizations.md#what-the-organization-carries-from-the-moment-it-exists)
before testing enforcement. TLS inspection alone does not enable DLP.

A signed MSI or PKG is separate from source code and deployment configuration. Endpoint
packaging needs suitable platform signing identities; installing a package does not prove
that steering is active or that the client trusts inspected HTTPS.

Passing startup checks does not establish endurance, recovery, audited isolation, or
production readiness. [Verification](verification.md) explains how to record those claims
separately. Report vulnerabilities through the private channel in [SECURITY.md](../SECURITY.md).
