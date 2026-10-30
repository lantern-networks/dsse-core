# 0.4.0 experimental

**Experimental release; not certified for production.** These documents describe
the 0.4.0 experimental distribution. [Acceptance and limitations](verification.md)
records what was measured on the released server images and endpoint packages,
the known issues, and the acceptance items that remain open. Use the
`release-manifest.json` published with the release to identify the exact assets.
0.4.0 is accepted for fresh installations only. Existing 0.3.1 installations, if
any, require separate upgrade and data-migration validation; the legacy upgrade
notes are reference material.
The bundled MinIO service is removed. External S3 archival is optional; a
deployment without it retains aged audit history in its persistent local hot store.

## Distribution

The 0.3.1 experimental release uploaded five assets: a generic macOS PKG, a generic
Windows x64 MSI, a source CycloneDX SBOM, `release-manifest.json`, and `SHA256SUMS`.
GitHub also provides source archives. Servers and Connectors are built from source.

0.4.0 keeps those installation paths and adds an explicitly checksummed OSS source
archive and an English documentation archive. The seven release assets are:

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

## Server container images

0.4.0 also publishes the five server images as linux/amd64 container images. They
are the exact images, by digest, that the acceptance installation ran. Each passed
the release image scan with no blocking high or critical finding.

| Plan setting | Image |
|---|---|
| `service_image` | `ghcr.io/lantern-networks/dsse-service@sha256:6a799afd89182a73e12566954730a0a561fc871c97ce95f3e1002eee7cb8c228` |
| `console_image` | `ghcr.io/lantern-networks/dsse-console@sha256:a5eb525e0af1b345e514d99b46bda0ad10777285b20cac4cf1d90f1c140a217f` |
| `data_layer.etcd_image` | `ghcr.io/lantern-networks/dsse-etcd@sha256:46c7e4608e1b3e08e29cb4d57230c19144170318d17ca7ddd708ba749c572984` |
| `data_layer.postgres_image` | `ghcr.io/lantern-networks/dsse-postgres@sha256:e835b85c2125e6fe04134d13094065398dfa39e27a34d4d0de55008a5cafd18a` |
| `data_layer.postgres_tools_image` | `ghcr.io/lantern-networks/dsse-postgres-tools@sha256:48a9b7badd6045c24230be413653a108e8d568cafb990358ea286dc5f6773d13` |

The `0.4.0` tag names the same images; use the digests in a plan. The service and
Console images carry the label `org.opencontainers.image.revision` set to
`source-facfca560389c3221d1ee454ed14f12f63531986afef096761eaf4f1851b12b0`, and
setup preflight refuses them unless the plan's `image_revision` has that value.
Set `data_layer.postgres_major` to `18`. HAProxy and ClickHouse are used from
their upstream images at the digests the installer pins. See [Building](../../building.md)
for the plan settings and for building the same images from source instead.

`dsse-postgres` is built from Zalando Spilo on Ubuntu 22.04 with PostgreSQL 18.6,
Patroni 4.1.5 and WAL-G built from source. It contains third-party software under
its own licenses, including GPL-licensed packages. Their sources are available from
Ubuntu and the respective upstream projects; the build recipe is in the source
archive (`deploy/spilo-4.1-p2.patch`, `scripts/build_spilo_source.sh`).

No Linux endpoint installer, macOS Intel package, Windows ARM64 package, EXE
bootstrapper, or arm64 server image is added by this release. The Linux services,
Console, installer and Connector can also be built from source using
[Building](../../building.md); the Docker build recipes remain in the source tree.
Supported native architectures follow the tested 0.3.1 distribution;
cross-compilation is not OS acceptance.

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
[Acceptance and limitations](verification.md) before installing.

For the layouts, start with [Three entrances with Region-scoped Edge pools](install-multi-edge.md):
role and failure diagrams, profile selection, machine/network preparation, plan and
DNS examples, authority bootstrap, state admission, Edge carries and endpoint acceptance.
