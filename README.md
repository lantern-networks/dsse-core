# dsse-core

**Lantern DSSE** is developed and maintained by
[Lantern Networks, Inc.](https://lantern-networks.co.jp/).
This is its official source repository, published as `dsse-core` under Apache-2.0.
See the [company website](https://lantern-networks.co.jp/) for the project overview
and [company information](https://lantern-networks.co.jp/company/).

An open-source Secure Service Edge (SSE / ZTNA) implementation for self-hosted labs.
DSSE provides TLS inspection, mTLS device identity, policy enforcement, DNS control, and
access to private applications through outbound connectors. The repository contains
Go packages, runnable services, an Admin Console, and Windows and macOS endpoint agents.

**This is an experimental release, not production-ready.** Interfaces, defaults, and configuration may
change without a migration path. Use an isolated lab with recoverable devices and data.
A successful installation check is not evidence of long-duration reliability or of a
security audit. It has not been independently run at length by anyone who did not write it.
See the [threat model](docs/threat-model.md) and each platform's limitations.

Signed endpoint packages, checksums and known release limitations are listed in
[GitHub Releases](https://github.com/lantern-networks/dsse-core/releases).

Start with the [documentation index](docs/README.md) for a reading path by role and
the [verification guide](docs/verification.md) for what each check establishes.

## Maintenance status

Development of 0.3.1 is focused on everyday reliability. See
[maintenance and 0.3.1 progress](docs/maintenance.md) for implemented fixes,
remaining release checks and the target week. Development changes are not yet
part of the published 0.3.0 experimental release.

## Install and start a deployment

Follow these pages in order. All commands use this repository's root, where `go.mod`,
`cmd/`, `deploy/`, and `schemas/` live.

1. [Deployment](docs/deployment.md): prerequisites, build, plan, start, bootstrap the
   administrator, and verify. Includes plans for **three regions with one node each**
   and for a single-machine lab.
2. [First use](docs/after-verify.md): trust the Console certificate, sign in with MFA,
   and prepare the first customer organization.
3. [Organizations](docs/organizations.md): configure its authorities and policies,
   then obtain a signed device profile and one-time enrolment token.
4. Install an endpoint: [Windows](docs/windows-agent.md) or [macOS](docs/macos-agent.md).
   Both require a suitable signed package; source code alone does not supply signing identities.
5. [Connectors](docs/connector.md): publish a private application and test access from
   the enrolled endpoint.

Completion means the deployment checks pass, the administrator can sign in, and a real
endpoint passes its local verifier and can reach an allowed application. Review every
failed or unanswered check. Verify a denied flow as well before relying on a policy.

For a smaller code demonstration, the [local API quickstart](docs/getting-started.md)
runs one Edge on loopback. It is **not a deployment** and does not install an endpoint.

## Architecture and operations

| Guide | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Control plane, Edge, identity, inspection, and configuration distribution |
| [PKI](docs/pki.md) | CA structure, key custody, automatic renewal, and operator-managed rotation |
| [IdP integration](docs/idp.md) | Customer sign-in, claims, TLS, and current assurance limits |
| [Egress policy](docs/egress-policy.md) | Internet Access rules, inspection, bypass, DLP, and verification |
| [East-West policy](docs/east-west-policy.md) | Internal access, enforcement stages, and out-of-band step-up |
| [DLP](docs/dlp.md) | Upload detectors, policy attachment, actions, and coverage limits |
| [Administration](docs/administration.md) | Roles, customer delegation, elevation, and recovery authority |
| [Audit and data](docs/audit-and-data.md) | Evidence, delivery, retention, exports, and data handling |
| [Release overview](docs/release-overview.md) | Evaluation scope, defaults, limitations, and release evidence status |
| [Building](docs/building.md) | Service images, native binaries, and endpoint packaging prerequisites |
| [Operator tools](docs/operator-tools.md) | Verify profiles and signing keys; sign update manifests |
| [Agent updates](docs/agent-updates.md) | Publish signed packages to enrolled devices |
| [Operations](docs/operations.md) | Routine checks, change control, state, and recovery preparation |
| [Troubleshooting](docs/troubleshooting.md) | Diagnose deployment, endpoint, policy, and update failures |
| [Egress broker](egress-broker/README.md) | Optional curl-impersonate transport; the standard deployment uses Go HTTP/TLS |

The policy evaluator is default-deny. The Console's initial organization policy can
explicitly allow and inspect all traffic, and connector access starts in OBSERVE mode;
[review these defaults](docs/organizations.md#what-the-organization-carries-from-the-moment-it-exists)
as part of setup.

## Use as a Go library

```sh
go get github.com/lantern-networks/dsse-core/...
```

Packages include `policy`, `decision`, `swg`, `inspection`, `tenantca`, `revocation`,
`dnsresolver`, and `connector`. From a checkout:

```sh
go build ./...
go test ./...
```

The [egress broker](egress-broker/README.md) is a nested module with native dependencies;
these commands do not build or test it. Platform-specific endpoint builds are described
in [Building](docs/building.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the Developer Certificate of Origin and
contribution checks. Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Licensing behavior

With no vendor keys configured, the deployment has no licence-based seat limit. A signed
licence, when configured, declares a certified scope and may refuse new enrolments beyond
that scope. It must not stop existing traffic, halt an Edge, or disable features.
The source is available under Apache-2.0, including this logic.

## License

[Apache-2.0](LICENSE). Native components used by the egress broker have additional licence
terms; see [THIRD-PARTY.md](egress-broker/THIRD-PARTY.md) and the licence texts it links.
