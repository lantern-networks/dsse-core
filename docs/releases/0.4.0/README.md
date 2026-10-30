# 0.4.0 distribution review

**Review candidate; unpublished.** These documents describe the proposed 0.4.0
experimental distribution. They do not announce a release or authorize production
deployment. Package signing, acceptance and outstanding review findings are separate
release gates. Use the manifest accompanying the exact candidate you evaluate.
0.4.0 acceptance currently targets fresh installations. Existing 0.3.1
installations, if any, require separate upgrade and data-migration validation;
the legacy upgrade notes are reference material, not a publication gate for this candidate.
The bundled MinIO service is removed. External S3 archival is optional; a
deployment without it retains aged audit history in its persistent local hot store.

## Distribution

The 0.3.1 experimental release uploaded five assets: a generic macOS PKG, a generic
Windows x64 MSI, a source CycloneDX SBOM, `release-manifest.json`, and `SHA256SUMS`.
GitHub also provides source archives. Servers and Connectors are built from source.

0.4.0 keeps those installation paths and adds an explicitly checksummed OSS source
archive and an English documentation archive. The proposed seven release assets are:

| Asset | Contents and acceptance |
|---|---|
| `LanternDsseAgent-0.4.0-<build>.pkg` | Apple silicon agent, Network Extension and helpers; Developer ID signing, notarization and stapling required |
| `DsseAgent-0.4.0-windows-x64.msi` | Generic x64 agent and helpers; EV Authenticode signatures and timestamps, verified Microsoft-signed driver required |
| `dsse-0.4.0-source.tar.gz` | Complete reviewed OSS tree, English documentation, source build recipes and licenses; no Git history or deployment state |
| `dsse-0.4.0-docs-en.tar.gz` | English operator documentation and example plans from that source tree |
| `dsse-0.4.0-source-sbom.cdx.json` | Root Go-module dependency inventory; scope and omissions declared in the manifest |
| `release-manifest.json` | Source content identity, artifact sizes and hashes, signature/scan/acceptance status and release qualification |
| `SHA256SUMS` | SHA256 of every other delivered asset, including the manifest |

Only files actually present may be listed as delivered. A missing platform package,
failed scan or pending acceptance must remain visible. Checksums alone do not establish
authenticity; verify the signed packages and obtain checksums through a trusted channel.
The source SBOM does not inventory every native dependency, kernel driver or container
base image. The 0.4.0 distribution does not include an egress-broker executable or
image and does not qualify browser-mimic mode. Experimental broker source remains in
the source archive but is outside the packaged deployment and image scan inventory.

No Linux endpoint installer, macOS Intel package, Windows ARM64 package, EXE
bootstrapper or prebuilt server/container release is added by this proposal. Build
the Linux services, Console, installer and Connector using [Building](../../building.md).
The Docker build recipes remain available in the source tree. Supported native
architectures follow the tested 0.3.1 distribution; cross-compilation is not OS acceptance.

## Deployment material remains separate

The same signed endpoint package must work across independent deployments and tenants.
Do not embed profiles, enrollment tokens, customer CAs, verification pins, device
identities, recovery destinations or live configuration in public assets. Provision
these separately through the verified installation path. A new tenant does not need
a new PKG/MSI or new plane hostnames. Each regional Portal name is shared by its
regional Edges and tenants. The reviewed target has three independent entrances:
one Region uses a shared three-Edge pool; three Regions use one dedicated
CP+HAProxy host and two dedicated Edges in each Region, with each physical
entrance using only its own two Edges. Grants and revocation are shared across
all six Edges. See the installation guide and acceptance
record for entrance-only failure and one-node-at-a-time upgrade checks on the
actual deployment.

Read [Changes since 0.3.1](changes.md), [Installation and legacy upgrade reference](upgrade.md), and
[Acceptance and limitations](verification.md) before selecting a candidate.

For the layouts, start with [Three entrances with Region-scoped Edge pools](install-multi-edge.md):
role and failure diagrams, profile selection, machine/network preparation, plan and
DNS examples, authority bootstrap, state admission, Edge carries and endpoint acceptance.
