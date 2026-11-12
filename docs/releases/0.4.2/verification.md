# Acceptance

0.4.2 is an experimental release. This page records what was installed and checked with
the 0.4.2 builds. Read [Release overview and known limitations](../../release-overview.md)
before deciding where to deploy it.

## The release builds

The release images and the release `dsse-install` were installed on new Linux hosts
(Ubuntu 24.04, x86-64, AWS Tokyo) that had Docker and nothing else, with
`dsse-install -up` and the release manifest. Port 443 accepted every address; only SSH
was limited to the operator.

| Layout | How | Checked |
|---|---|---|
| One machine | `-up -deployment … -address …`, no plan file | Six steps in 3 minutes 30 seconds. `-verify`: 50 checks passed, none failed; one was not applicable because no customer organization existed yet |
| Three Regions, one machine each | `-up -plan three-regions.json -ssh`, one command on the first machine | Sixteen steps in 4 minutes 20 seconds. `-verify`: 61 checks passed, none failed; two were not applicable (no customer organization yet; standby control planes do not answer roster reads) |

The orders of the other published plans are run by the installer's tests.

## Devices on the one-machine installation

Ten organizations, twenty Connectors (the release binary, two per organization) and
1,000 simulated devices were added to the one-machine installation (4 vCPU, 16 GB)
through the administration API. The simulated devices speak the agent's protocol: they
enrol with one-time tokens, hold their connection, send heartbeats every 15 seconds, poll
policy every 60 seconds, and open flows to an internal application through their
organization's Connectors.

| Operation, 10 minutes | Count | Failed | Median | 99th percentile |
|---|---|---|---|---|
| Enrolment | 1,000 | 0 | 39 ms | 51 ms |
| Connect | 1,000 | 0 | 2.5 ms | 5.7 ms |
| Heartbeat | 38,412 | 0 | 0.5 ms | 25 ms |
| Policy poll | 9,449 | 0 | 0.6 ms | 1.0 ms |
| Flow to the organization's application | 18,950 | 0 | 1.4 ms | 3.3 ms |
| Inspected internet flow | 973 | 0 | 32 ms | 132 ms |
| Flow to another organization's application | 1,892 | all refused | 1.1 ms | 2.6 ms |

Before the release, a build of the same heartbeat, entrance and audit-spool changes ran
10,006 simulated devices in ten organizations on one machine of the same size for seven
minutes with no failed heartbeat, flow or policy poll.

## Known limits at this scale

- Enrolment slows as an organization's fleet grows: about 30 devices a second into an
  empty deployment, 3 to 4 a second with 10,000 devices enrolled. An enrolment that
  times out leaves its token spent; issue a new token for that device.
- An organization holds at most 200 unspent enrolment tokens. Issue and enrol in rounds.
- An Edge ships audit records to the control plane one at a time. Under sustained load
  above what it can ship, the Edge's spool fills and further records stay in the Edge's
  own log.

## A Windows device

A Windows 10 x64 PC was enrolled into a one-machine installation of the release images
through the administration Console, following [Windows agent](../../windows-agent.md).

| Step | Checked |
|---|---|
| Install the published 0.4.1 MSI with `CONFIG`, `TOKEN` and `PIN` | The device enrolled and steering armed 27 seconds after the installer started; the Console listed it at 0.4.1 |
| Install the 0.4.2 MSI over it with `CONFIG` and `PIN`, without `TOKEN` | The installer finished in 43 seconds. The device certificate and enrolment time were unchanged, the agent did not enrol again, and the Console showed the same single device at 0.4.2 |
| Allow one site and deny another | The allowed site opened; the denied site showed the block page on the first request; both appeared in the Console log with the device's name |
| Uninstall with the 0.4.2 MSI | The services, the organization's interception root and the CA environment variables were removed, and HTTPS went direct again |

`verify-windows-install.ps1` reported three failures after the upgrade, all in its
strict-revocation checks: under interception Windows reports `RevocationStatusUnknown`,
as it did with 0.4.1.

## Packages and images

- The MSI carries EV Authenticode signatures and timestamps on the package and its six
  executables, which are built with Go 1.27.4. The Windows packaging tests passed. Its
  driver is the Microsoft-signed file shipped in 0.4.0, and its upgrade code is that of
  0.4.1.
- The macOS package is built from the same source with Go 1.27.4, Developer ID signed,
  notarized with the ticket stapled, and accepted by Gatekeeper for both the package and
  the application. Endpoint acceptance used Windows.
- The five server images and the HAProxy and ClickHouse images the installer pins were
  scanned with Trivy. None has a high or critical finding, apart from the WAL-G
  version-mapping exception described in [Dependency versions](../../dependency-versions.md).
