# Acceptance

0.4.3 is an experimental release. This page records what was installed and checked with
the 0.4.3 builds. Read [Release overview and known limitations](../../release-overview.md)
before deciding where to deploy it.

## The release builds

The release images and the release `dsse-install` were installed on new Linux hosts
(Ubuntu 24.04, x86-64, AWS Tokyo) that had Docker and nothing else. Port 443 accepted
every address; only SSH was limited to the operator.

| Layout | How | Checked |
|---|---|---|
| One machine | `-up -deployment … -address …` with the release manifest, no plan file | Six steps in 3 minutes 37 seconds. `-verify`: 50 checks passed, none failed; one was not applicable because no customer organization existed yet |
| Three Regions, one machine each, upgraded from 0.4.2 | The published 0.4.2 installed with `-up -plan three-regions.json -ssh`; two organizations, four 0.4.2 Connectors and 300 devices added; then each machine moved to 0.4.3 with `dsse-install -upgrade`, one machine at a time | `-verify` after the last machine: 61 checks passed, none failed; two were not applicable. The deployment's organizations, devices, Connectors, rules, Sites and applications read the same before and after (33 items) |

### While the three Regions were upgraded

Each machine's `-upgrade` replaced its services in 17 to 36 seconds.

- The devices attached to the Region being upgraded reconnected by themselves. Its Edge
  stopped serving and served again within 25 seconds; the simulated devices, which wait
  between attempts up to 16 seconds, were all back within 40 seconds.
- Devices attached to the other Regions stayed connected.
- Private applications behind Connectors attached to the Region being upgraded failed for
  about half a minute, from every Region, while the Connectors moved.
- After the upgrade, Sites, connector commands and connector enrolment worked from every
  Region, including after the database's primary had moved and moved back.

## Devices on the one-machine installation

Five organizations, five Connectors (the release binary, one per organization) and 1,000
simulated devices were added to the one-machine installation (4 vCPU, 16 GB) through the
administration API. Each organization's Site registered the server network, its rule
allowed its own application's port only, and its Connector Access posture enforced the
rules. The simulated devices speak the agent's protocol: they enrol with one-time tokens,
hold their connection, send heartbeats, poll policy, and open flows to their
organization's application through its Connector, to the internet, and to another
organization's application.

| Operation, 7 minutes, including one Edge restart | Count | Failed | Median | 99th percentile |
|---|---|---|---|---|
| Enrolment | 1,000 | 0 | 42 ms | 58 ms |
| Heartbeat | 26,509 | 2 | 0.8 ms | 33 ms |
| Policy poll | 6,513 | 0 | 0.9 ms | 4.3 ms |
| Flow to the organization's application | 38,904 | 55 | 2.0 ms | 9.0 ms |
| Inspected internet flow | 1,279 | 0 | 25 ms | 87 ms |
| Flow to another organization's application | 6,480 | all refused | 0.7 ms | 2.0 ms |

The failures are those of the Edge restart: every device reconnected in the next ten
seconds.

## A Mac and a Windows device

A Mac (Apple silicon) and a Windows PC were taken through the order a customer follows,
on a one-machine installation of the published 0.4.2 with a Site, its network and a 0.4.2
Connector. The organization, its certificates, Site, network, Connector and device sets,
and every rule, were made in the administration Console. The server build and the packages
used here were made from the 0.4.3 source before its last change, which decides a flow the
device names by the rules written for that name; that change was then installed on the same
server and checked with a simulated device. The agent code is the release's, and the release
packages differ from the ones used here only in the source identity they carry.

| Step | macOS | Windows |
|---|---|---|
| Install the published 0.4.2 package and enrol | Steering, inspected internet, the internal application through the Connector | Enrolled in 16 seconds; steering armed 20 seconds after the agent started |
| Move the server to 0.4.3 with `-upgrade` | The device kept its enrolment; it lost its connection for about 35 seconds and reconnected by itself | The device kept its enrolment and reconnected 8 seconds after its connection closed |
| Install the 0.4.3 package over 0.4.2 | Installed alone, without setup files beside it. Same enrolment, version 0.4.3, name lookups answered by the Edge; `dsse-verify-install` passed | `CONFIG` and `PIN`, no `TOKEN`: 32 seconds, same device certificate and enrolment, one device row at 0.4.3; `verify-windows-install.ps1` passed, with three revocation questions not applicable |
| Allow and deny | `www.iana.org` opened, `example.org` was refused, the internal application opened; all three appear in the Console log with the device's name | The same, with the refusal page on the first request |
| Uninstall | Both proxy configurations removed and the extension set to be removed at the next restart; HTTPS direct again | The services and the organization's interception root removed; HTTPS direct again |

## Packages and images

- The MSI carries EV Authenticode signatures and timestamps on the package and its six
  executables, which are built with Go 1.27.4. The Windows packaging tests passed. Its
  driver is the Microsoft-signed file shipped in 0.4.0, and its upgrade code is that of
  0.4.2.
- The macOS package is built from the same source with Go 1.27.4, Developer ID signed,
  notarized with the ticket stapled, and accepted by Gatekeeper for both the package and
  the application.
- The five server images and the HAProxy and ClickHouse images the installer pins were
  scanned with Trivy. None has a high or critical finding, apart from the WAL-G
  version-mapping exception described in [Dependency versions](../../dependency-versions.md).

## Known limits

- An organization holds at most 200 unspent enrolment tokens. Issue and enrol in rounds.
- While a machine's services are replaced, a device's first connection to it can be answered
  with another of the machine's certificates; the device refuses it and connects again.
- On a deployment of several Regions, a log query is answered from one Region's records; see
  [Audit and data](../../audit-and-data.md#find-and-correlate-an-event).
