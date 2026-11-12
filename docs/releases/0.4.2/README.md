# 0.4.2 experimental

**Experimental release; not certified for production.** 0.4.2 is a maintenance update of
0.4.1: one command installs a machine, an Edge carries more devices, and every binary is
rebuilt with a patched Go. It keeps the 0.4.1 layouts, plan format and package names.
Read [Changes since 0.4.1](changes.md), [Moving from 0.4.1](upgrade.md) and
[Acceptance](verification.md) before installing. Use the `release-manifest.json`
published with the release to identify the exact assets. 0.4.2 is accepted for fresh
server installations and for upgrading a Windows device enrolled with 0.4.1.

## Distribution

| Asset | Contents |
|---|---|
| `dsse-install-0.4.2-linux-amd64`, `dsse-install-0.4.2-linux-arm64` | The installer for the first machine of a deployment; a static binary that needs Docker and nothing else |
| `LanternDsseAgent-0.4.2-20261112211330.pkg` | Apple silicon agent, Network Extension and helpers; Developer ID signed, notarized and stapled |
| `DsseAgent-0.4.2-windows-x64.msi` | Generic x64 agent and helpers; EV Authenticode signatures and timestamps; the Microsoft-signed driver is the same file as in 0.4.0 |
| `dsse-0.4.2-source.tar.gz` | Complete OSS tree of the release tag, English documentation, source build recipes and licenses; no Git history or deployment state |
| `dsse-0.4.2-docs-en.tar.gz` | English operator documentation and example plans from that tree |
| `dsse-0.4.2-source-sbom.cdx.json` | Root Go-module dependency inventory; scope and omissions declared in the manifest |
| `release-manifest.json` | Source content identity, artifact sizes and hashes, image references, signature, scan and acceptance status; `dsse-install -release-manifest` reads it |
| `SHA256SUMS` | SHA256 of every other asset, including the manifest |

The five server images, the installer binaries, the MSI and the PKG were all built from
one source tree: the public commit `7fa0ace88d53fe59bffe539d40f9df5cdcf7d24f`, whose content identity is
`source-84f7283e07c1f6915fe157670d87d6170f1f903ef0930ef946630f36fcbdc6f0`. The release
tag adds documentation only. Checksums alone do not establish authenticity; verify the
signed packages and obtain checksums through a trusted channel. The source SBOM does not
inventory every native dependency, kernel driver or container base image.

## Server container images

0.4.2 publishes the five server images as linux/amd64 container images. They are the
exact images, by digest, that the acceptance installations ran.

| Plan setting | Image |
|---|---|
| `service_image` | `ghcr.io/lantern-networks/dsse-service@sha256:467712bcc31f99b1d1b30ca5d934fb44043c41870836ef16c3da542464582bdb` |
| `console_image` | `ghcr.io/lantern-networks/dsse-console@sha256:6a28211aa41e5e2a1b07f873083aa8b560f92fb9d5c105e73a98ba512b9ec9f3` |
| `data_layer.etcd_image` | `ghcr.io/lantern-networks/dsse-etcd@sha256:769e9fd01ee099cddfd9ef84ef66d857e11a50b1aa4457e947e183f8dd686cd4` |
| `data_layer.postgres_image` | `ghcr.io/lantern-networks/dsse-postgres@sha256:a7c3052b009b128b0e2c7ddb5e8e6c4ce4c06e0be8a2e7338fc008efca080703` |
| `data_layer.postgres_tools_image` | `ghcr.io/lantern-networks/dsse-postgres-tools@sha256:0410d151ba037d8b64229f07548ce8ca34f1090225d4e8a4a25f9ed13011c5cb` |

The `0.4.2` tag names the same images. The service and Console images carry the label
`org.opencontainers.image.revision` set to
`source-84f7283e07c1f6915fe157670d87d6170f1f903ef0930ef946630f36fcbdc6f0`, and setup
preflight refuses them unless the plan's `image_revision` has that value. HAProxy and
ClickHouse are used from their upstream images at the digests the installer pins; see
[Dependency versions](../../dependency-versions.md).

### Using the published images

Pass the published manifest to the installer; it supplies the image references, the
packages' publisher (`M4U8GSBL6C`) and the PostgreSQL major:

```sh
dsse-install -up -deployment dsse.example.com -address 10.20.1.10 \
  -admin-email admin@example.com -dir /opt/dsse/region-a \
  -release-manifest release-manifest.json
```

[Deployment](../../deployment.md#run-the-order-with--up) describes the names to create
first and the plans with several machines. A plan may still carry the values itself:

```json
{
  "image_revision": "source-84f7283e07c1f6915fe157670d87d6170f1f903ef0930ef946630f36fcbdc6f0",
  "service_image": "ghcr.io/lantern-networks/dsse-service@sha256:467712bcc31f99b1d1b30ca5d934fb44043c41870836ef16c3da542464582bdb",
  "console_image": "ghcr.io/lantern-networks/dsse-console@sha256:6a28211aa41e5e2a1b07f873083aa8b560f92fb9d5c105e73a98ba512b9ec9f3",
  "data_layer": {
    "etcd_image": "ghcr.io/lantern-networks/dsse-etcd@sha256:769e9fd01ee099cddfd9ef84ef66d857e11a50b1aa4457e947e183f8dd686cd4",
    "postgres_image": "ghcr.io/lantern-networks/dsse-postgres@sha256:a7c3052b009b128b0e2c7ddb5e8e6c4ce4c06e0be8a2e7338fc008efca080703",
    "postgres_tools_image": "ghcr.io/lantern-networks/dsse-postgres-tools@sha256:0410d151ba037d8b64229f07548ce8ca34f1090225d4e8a4a25f9ed13011c5cb",
    "postgres_major": 18
  }
}
```

The published images run on x86-64 (linux/amd64) hosts.

### Checking the packages

Check each package before installing it, in addition to `SHA256SUMS`:

- macOS: `pkgutil --check-signature LanternDsseAgent-0.4.2-20261112211330.pkg` reports
  `Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)` and
  `Notarization: trusted by the Apple notary service`, and
  `spctl -a -vvv -t install` on the package reports `accepted` with
  `source=Notarized Developer ID`.
- Windows: `Get-AuthenticodeSignature .\DsseAgent-0.4.2-windows-x64.msi` reports
  `Valid`, and the signer certificate's thumbprint is
  `0E10AB8EC192B4313E472A3CA0723B2D07123923`.

### Checking the images yourself

You can check the images with this repository and the registry alone:

- **Digest.** `docker pull` by the digests above, or `docker buildx imagetools
  inspect`, needs no sign-in. A digest names exactly one image.
- **Source.** The images, the installer binaries, the MSI and the PKG carry the content
  identity `source-84f7283e…` of the public commit `7fa0ace88d53fe59bffe539d40f9df5cdcf7d24f`, which you can check
  from a clone:

  ```sh
  mkdir /tmp/dsse-0.4.2-source
  git archive 7fa0ace88d53fe59bffe539d40f9df5cdcf7d24f | tar -x -C /tmp/dsse-0.4.2-source
  cd /tmp/dsse-0.4.2-source
  go run ./scripts/verify_source_content_id.go -root . \
    -expected source-84f7283e07c1f6915fe157670d87d6170f1f903ef0930ef946630f36fcbdc6f0
  ```

  `git diff 7fa0ace88d53fe59bffe539d40f9df5cdcf7d24f v0.4.2-experimental` shows that the release tag adds only
  documentation.
- **Vulnerabilities.** Scan the same digests with your own scanner, for example
  `trivy image --platform linux/amd64 <image>@sha256:<digest>`. The release gate found no
  blocking high or critical finding; the one version-mapping exception is described in
  [Dependency versions](../../dependency-versions.md).

The images are not bit-for-bit reproducible: the service binaries embed their build
time, and the builds install the OS package updates current at build time. A rebuild
from the same commit has a different digest. It is not the verified release image:
generate its inventory and scan it before use.

`dsse-postgres` is built from Zalando Spilo on Ubuntu 22.04 with PostgreSQL 18.6,
Patroni 4.1.5 and WAL-G built from source. It contains third-party software under its
own licenses, including GPL-licensed packages. Their sources are available from Ubuntu
and the respective upstream projects; the build recipe is in the source archive
(`deploy/spilo-4.1-p2.patch`, `scripts/build_spilo_source.sh`).

## Deployment material remains separate

The same signed endpoint package works across independent deployments and
organizations. Profiles, enrolment tokens, organization CAs, verification pins, device
identities and recovery destinations are provisioned separately through the verified
installation path; they are not in any public asset. A new organization does not need
a new PKG or MSI.
