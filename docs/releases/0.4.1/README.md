# 0.4.1 experimental

**Experimental release; not certified for production.** 0.4.1 is a maintenance and
security update of 0.4.0. It keeps the 0.4.0 layouts, plan format and package names.
Read [Changes since 0.4.0](changes.md), [Moving from 0.4.0](upgrade.md) and
[Acceptance](verification.md) before installing. Use the `release-manifest.json`
published with the release to identify the exact assets. 0.4.1 is accepted for fresh
installations.

## Distribution

| Asset | Contents |
|---|---|
| `LanternDsseAgent-0.4.1-20261109092818.pkg` | Apple silicon agent, Network Extension and helpers; Developer ID signed, notarized and stapled |
| `DsseAgent-0.4.1-windows-x64.msi` | Generic x64 agent and helpers; EV Authenticode signatures and timestamps; the Microsoft-signed driver is the same file as in 0.4.0 |
| `dsse-0.4.1-source.tar.gz` | Complete OSS tree of the release tag, English documentation, source build recipes and licenses; no Git history or deployment state |
| `dsse-0.4.1-docs-en.tar.gz` | English operator documentation and example plans from that tree |
| `dsse-0.4.1-source-sbom.cdx.json` | Root Go-module dependency inventory; scope and omissions declared in the manifest |
| `release-manifest.json` | Source content identity, artifact sizes and hashes, signature, scan and acceptance status |
| `SHA256SUMS` | SHA256 of every other asset, including the manifest |

The five server images, the MSI and the PKG were all built from one source tree: the
public commit `1fbcb678e6fee66ffec043bb7ee1325af550fec4`, whose content identity is
`source-bfafcfd026d5bfe34a226d93d55347a2dd201cd5fde2b5f2b6b861bf8e3f2889`. The release
tag adds documentation and one test change: two `edgeplane` tests now set the Edge's IPv6
egress themselves instead of depending on the machine that runs them. No product code
differs. Checksums alone do not establish authenticity; verify the
signed packages and obtain checksums through a trusted channel. The source SBOM does not
inventory every native dependency, kernel driver or container base image.

## Server container images

0.4.1 publishes the five server images as linux/amd64 container images. They are the
exact images, by digest, that the acceptance installations ran.

| Plan setting | Image |
|---|---|
| `service_image` | `ghcr.io/lantern-networks/dsse-service@sha256:74cb1b4735c6fd11c1569363285c7d7ef2c3eede8953a1cb8fa26b4626b6a4b6` |
| `console_image` | `ghcr.io/lantern-networks/dsse-console@sha256:e090bd58ef1d92a2c0a4ef630f311db5d4c17c0a398b58ca4daaafa3218457d9` |
| `data_layer.etcd_image` | `ghcr.io/lantern-networks/dsse-etcd@sha256:27b748ee6c6fa6ddf48c4481151ab4258d59d34d6d8a6c8fedaf1c4f32da13a9` |
| `data_layer.postgres_image` | `ghcr.io/lantern-networks/dsse-postgres@sha256:9ce0dea526d1a401be8d28701a9585f0f9b1bd2eb236b0baa2a90eec85f3e5fe` |
| `data_layer.postgres_tools_image` | `ghcr.io/lantern-networks/dsse-postgres-tools@sha256:c1fd6f2ac9c448daba984dbec7f200be9baba6b5a42a4d5882eb15ac866fa36f` |

The `0.4.1` tag names the same images; use the digests in a plan. The service and
Console images carry the label `org.opencontainers.image.revision` set to
`source-bfafcfd026d5bfe34a226d93d55347a2dd201cd5fde2b5f2b6b861bf8e3f2889`, and setup
preflight refuses them unless the plan's `image_revision` has that value. HAProxy and
ClickHouse are used from their upstream images at the digests the installer pins; see
[Dependency versions](../../dependency-versions.md).

### Using the published images

Add these settings to a plan, beside `deployment`, `agent_publisher` and `regions`:

```json
{
  "image_revision": "source-bfafcfd026d5bfe34a226d93d55347a2dd201cd5fde2b5f2b6b861bf8e3f2889",
  "service_image": "ghcr.io/lantern-networks/dsse-service@sha256:74cb1b4735c6fd11c1569363285c7d7ef2c3eede8953a1cb8fa26b4626b6a4b6",
  "console_image": "ghcr.io/lantern-networks/dsse-console@sha256:e090bd58ef1d92a2c0a4ef630f311db5d4c17c0a398b58ca4daaafa3218457d9",
  "data_layer": {
    "etcd_image": "ghcr.io/lantern-networks/dsse-etcd@sha256:27b748ee6c6fa6ddf48c4481151ab4258d59d34d6d8a6c8fedaf1c4f32da13a9",
    "postgres_image": "ghcr.io/lantern-networks/dsse-postgres@sha256:9ce0dea526d1a401be8d28701a9585f0f9b1bd2eb236b0baa2a90eec85f3e5fe",
    "postgres_tools_image": "ghcr.io/lantern-networks/dsse-postgres-tools@sha256:c1fd6f2ac9c448daba984dbec7f200be9baba6b5a42a4d5882eb15ac866fa36f",
    "postgres_major": 18
  }
}
```

For the packages published with this release, `agent_publisher` is `M4U8GSBL6C`. Then
follow [Deployment](../../deployment.md) from `-order`. The published images run on
x86-64 (linux/amd64) hosts.

### Checking the packages

Check each package before installing it, in addition to `SHA256SUMS`:

- macOS: `pkgutil --check-signature LanternDsseAgent-0.4.1-20261109092818.pkg` reports
  `Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)` and
  `Notarization: trusted by the Apple notary service`, and
  `spctl -a -vvv -t install` on the package reports `accepted` with
  `source=Notarized Developer ID`.
- Windows: `Get-AuthenticodeSignature .\DsseAgent-0.4.1-windows-x64.msi` reports
  `Valid`, and the signer certificate's thumbprint is
  `0E10AB8EC192B4313E472A3CA0723B2D07123923`.

### Checking the images yourself

You can check the images with this repository and the registry alone:

- **Digest.** `docker pull` by the digests above, or `docker buildx imagetools
  inspect`, needs no sign-in. A digest names exactly one image.
- **Source.** The images, the MSI and the PKG carry the content identity
  `source-bfafcfd0…` of the public commit `1fbcb678e6fee66ffec043bb7ee1325af550fec4`,
  which you can check from a clone:

  ```sh
  mkdir /tmp/dsse-0.4.1-source
  git archive 1fbcb678e6fee66ffec043bb7ee1325af550fec4 | tar -x -C /tmp/dsse-0.4.1-source
  cd /tmp/dsse-0.4.1-source
  go run ./scripts/verify_source_content_id.go -root . \
    -expected source-bfafcfd026d5bfe34a226d93d55347a2dd201cd5fde2b5f2b6b861bf8e3f2889
  ```

  `git diff 1fbcb678e6fee66ffec043bb7ee1325af550fec4 v0.4.1-experimental` shows that the
  release tag adds only documentation and that test change.
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
