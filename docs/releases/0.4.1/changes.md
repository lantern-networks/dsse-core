# Changes since 0.4.0

The baseline is the published `v0.4.0-experimental` source and its artifacts. See
[Acceptance](verification.md) for what was installed and checked.

## Security

| Area | 0.4.1 |
|---|---|
| Connector credentials | `POST /auth/events` is registered only in lab mode, and a session identifier is no longer read from the query string. A Connector's credentials cannot create a user's authenticated session |
| Steered connections | The address the egress guard checked is the address the Edge dials, so a name that resolves differently on a second lookup cannot reach a refused destination |
| East-west authentication | The authentication ceremony carries the person and, where both sides know it, the device. A ceremony without a person is refused, and the grant records who authenticated |
| Single-machine data store | etcd uses TLS with client certificates on a single machine too, as it does on several machines |
| Administrator activation | Activation is `POST /admin/activate` with the token in the body. An invitation link carries the token in the fragment (`/?activate#activate=…`), and the Console removes it from the address bar after reading it |
| Fleet capability reports | A report from a certificate that is not on the deployment's roster is refused before any write |
| Administrator sign-in | Sign-in attempts are rate-limited per source and account (5 per second, burst 20) with a per-source backstop (50 per second, burst 200), configurable with `DSSE_ADMIN_SIGNIN_*`. The Console applies the same limit per browser address. Account lockout remains |
| Health and metrics | `/healthz` answers anyone with `{"status":"ok"}` only. The node's details and `/metrics` are returned only to an administrator credential of the operator organization; give a metrics scraper a named API token with `admin.state.read`. A deployment with port 443 open to every address no longer describes itself to unauthenticated callers |
| Go modules | `golang.org/x/net` 0.62.0 and `golang.org/x/crypto` at the revision that fixes GO-2026-5932 |

## Installation

| Area | 0.4.1 |
|---|---|
| Authentication activation | `-order` for every plan now includes `-activate-auth`, and `-bootstrap-admin` writes the read-only token it needs. Revocation re-authentication, ceremony recovery, grant evidence and single-request grants are switched on in the single-machine and three-Region layouts as well |
| Names | The names report lists `console.<deployment>`, the origin of the Console's invitation links and sign-in returns, for every plan, and every door and portal name a plan's clients use |
| Single machine | The single-machine plan installs as [Deployment](../../deployment.md) describes. `-verify` recognises one machine by the plan's declared shape |
| Credentials | Every `-order` profile writes the first administrator's credentials to a file only its owner can read, and `-verify` reads the operator token from a file rather than the command line |
| Preflight and `-verify` | Preflight names an image it cannot find. `-verify` waits for the Edge, checks `agents.<deployment>`, and names the fix when a Region does not verify |
| Stopped entrances | An Edge beside a stopped entrance reaches the control plane through another, and a stopped Region entrance no longer hides the leading control plane from the other Regions |

## Edge and policy

| Area | 0.4.1 |
|---|---|
| Refusals | A browser receives a refusal page in Japanese or English with the site, the time and a reference number. Other clients receive a fixed JSON body with `decision`, `reason` and `reference` only. A failed upstream certificate also shows a readable page to a browser |
| Logs | A refused steered destination is logged with its name and the source address. An allowed row names its rule and the reason. Connector events are shipped to the control plane and appear in the Console's Connector stream |
| Steering exclusions | Exclusions reach every Edge through the configuration bundle. Windows receives dual-stack and drive-letter forms |
| Ranges | A destination defined as an address range matches the addresses inside it |

## Admin Console

| Area | 0.4.1 |
|---|---|
| Japanese screens | The remaining English and identifier-only text on the Japanese screens is translated |
| Several tabs | A write, or a change of Connector access mode, reaches the other open tabs |
| Agent releases | Choosing a signed release file fills the version, platforms and download address from that file |
| Sites | An administrator chooses the order of the entrances a site's Connectors use |
| Invitations | An invitation states its expiry in the organization's time zone |

## Endpoints and Connectors

| Area | 0.4.1 |
|---|---|
| Windows upgrade | Installing the 0.4.1 MSI over 0.4.0 keeps the enrolment, puts the profile's update keys and publisher into the updater's arguments and restarts it. The certificates 0.4.0 trusted for provisioning are recorded, so a later uninstall removes them |
| Windows checks | `verify-windows-install.ps1` runs on PowerShell 7, reports the home Region from the region list, and `-AfterUninstall` reports a kept registration instead of failing on it |
| Connectors | A Connector returning to its home entrance keeps the connections behind it. The control plane keeps each Connector's version, uptime and current entrance from the Edges' reports |

## Dependencies

etcd 3.7.3 (source-built), WAL-G built with current modules, Alpine 3.24.3 bases for the
product, Console and tools images, a rebuilt HAProxy 3.4.7 digest, WiX 7.0.1 for the MSI,
and the Go 1.27.3 toolchain pinned in every module. See
[Dependency versions](../../dependency-versions.md).
