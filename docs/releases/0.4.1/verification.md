# Acceptance

0.4.1 is an experimental release. This page records what was installed and checked with
the 0.4.1 builds. Read [Release overview and known limitations](../../release-overview.md)
before deciding where to deploy it.

## How it was installed

Every layout in the guides was installed on new Linux hosts (Ubuntu 24.04, x86-64, AWS
Tokyo) from the published plan examples, following [Deployment](../../deployment.md) and
the steps the installer's `-order` printed. Port 443 accepted every address; only SSH was
limited to the operator. The identity provider was Keycloak 26.8.2 with password and TOTP
sign-in. The endpoint was a Windows PC with the EV-signed MSI.

| Layout | Plan | Checked |
|---|---|---|
| One machine | `single-region.json` | `-verify` with no failure. A Windows device enrolled with the 0.4.0 MSI and upgraded to 0.4.1. Console setup, steering, allow and deny with log rows, a Connector to an internal application, step-up sign-in with the held connection resumed, revocation followed by a fresh sign-in, and uninstall |
| Three Regions, one machine each | `three-regions.json` | `-verify` with no failure. Console setup, a new Windows installation, allow and deny, a Connector, step-up sign-in with the held connection resumed. With region-a's entrance stopped, the Connector moved to region-b in 2 seconds and the device within 6 seconds; the Consoles of region-b and region-c accepted sign-in and changes. Uninstall |
| One Region, three machines | `one-region-three-independent-entries.json` | `-verify` with no failure. Console setup, a Windows installation, allow and deny with log rows, a Connector, administrator invitation, and uninstall |
| Three Regions with dedicated Edges | `three-regions-multi-edge.json` | `-verify` with no failure. With region-a's entrance stopped, the device and the Connector moved to region-b and reached the internal application, and region-b's Console accepted reads, rule changes and a revocation |

After each uninstall, ordinary networking returned; the interception root was removed
and a manually added deployment anchor was kept.

## The release builds

The release images, installer and MSI were installed again in the single-machine layout
on a new host:

- `-order` printed six steps. `-activate-auth` reached `phase: ready` in 50 seconds with
  four features, including revocation re-authentication.
- `-verify`: 50 checks passed, none failed. One was not applicable because no customer
  organization existed yet.
- Without credentials, `/healthz` answered only `{"status":"ok"}` and `/metrics` was
  refused.
- A Windows PC installed the release MSI with the files the Console issued for a new
  organization. It enrolled and steered; an allowed site opened under the organization's
  interception certificate, a refused site showed the refusal page on the first visit,
  and both appeared in the Console's logs with their rule and reason. The uninstall
  removed the interception root and ordinary networking returned.

## Packages and images

- The MSI carries EV Authenticode signatures and timestamps on the package and its
  executables. The Windows packaging tests passed. Its driver is the Microsoft-signed
  file shipped in 0.4.0.
- The macOS package is built from the same source, Developer ID signed, notarized with
  the ticket stapled, and accepted by Gatekeeper for both the package and the
  application. Endpoint acceptance used Windows.
- The five server images and the HAProxy and ClickHouse images the installer pins were
  scanned with Trivy. None has a high or critical finding, apart from the WAL-G
  version-mapping exception described in [Dependency versions](../../dependency-versions.md).
