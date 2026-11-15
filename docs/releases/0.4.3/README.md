# 0.4.3 experimental

**Experimental release; not certified for production.** 0.4.3 is a maintenance update of
0.4.2: a server moves to a new release with `dsse-install -upgrade`, the macOS agent's name
lookups are answered by its Edge, and an Edge starts again after a restart. It keeps the 0.4.2
layouts, plan format and package names. Read [Changes since 0.4.2](changes.md),
[Moving from 0.4.2](upgrade.md) and [Acceptance](verification.md) before installing. Use the
`release-manifest.json` published with the release to identify the exact assets. 0.4.3 is
accepted for fresh server installations, for upgrading a server installed with 0.4.2, and for
upgrading Windows and macOS devices enrolled with 0.4.2.

## Distribution

| Asset | Contents |
|---|---|
| `dsse-install-0.4.3-linux-amd64`, `dsse-install-0.4.3-linux-arm64` | The installer for the first machine of a deployment; a static binary that needs Docker and nothing else |
| `LanternDsseAgent-0.4.3-20261115073439.pkg` | Apple silicon agent, Network Extension and helpers; Developer ID signed, notarized and stapled |
| `DsseAgent-0.4.3-windows-x64.msi` | Generic x64 agent and helpers; EV Authenticode signatures and timestamps; the Microsoft-signed driver is the same file as in 0.4.0 |
| `dsse-0.4.3-source.tar.gz` | Complete OSS tree of the release tag, English documentation, source build recipes and licenses; no Git history or deployment state |
| `dsse-0.4.3-docs-en.tar.gz` | English operator documentation and example plans from that tree |
| `dsse-0.4.3-source-sbom.cdx.json` | Root Go-module dependency inventory; scope and omissions declared in the manifest |
| `release-manifest.json` | Source content identity, artifact sizes and hashes, image references, signature, scan and acceptance status; `dsse-install -release-manifest` reads it |
| `SHA256SUMS` | SHA256 of every other asset, including the manifest |

The five server images, the installer binaries, the MSI and the PKG were all built from
one source tree: the public commit `c06c2f619a995f789a5cfe1725649e1fb46af481`, whose content identity is
`source-144f4afa3671cb07972479225fab99a700dd2ce336ef0812af57937474f72c93`. The release
tag adds documentation only. Checksums alone do not establish authenticity; verify the
signed packages and obtain checksums through a trusted channel. The source SBOM does not
inventory every native dependency, kernel driver or container base image.

## Server container images

0.4.3 publishes the five server images as linux/amd64 container images. They are the
exact images, by digest, that the acceptance installations ran.

| Plan setting | Image |
|---|---|
| `service_image` | `ghcr.io/lantern-networks/dsse-service@sha256:284d08999f8e7be0aec2d9f3551b2f61d87e7bf6fe98b838e29052beaf308697` |
| `console_image` | `ghcr.io/lantern-networks/dsse-console@sha256:ca50f7e44e24781c2e45be2bbb2939e7cdfece38d4deb9cc8d0fe67a1722365c` |
| `data_layer.etcd_image` | `ghcr.io/lantern-networks/dsse-etcd@sha256:3f195e59100f5bb515fa679ec422574f20f6cb4eda9860a818a80d19658e2197` |
| `data_layer.postgres_image` | `ghcr.io/lantern-networks/dsse-postgres@sha256:110c4d06c377bfbdb7e69295186d13fd95626dc88b30d9b94c0ab8dd2f50df00` |
| `data_layer.postgres_tools_image` | `ghcr.io/lantern-networks/dsse-postgres-tools@sha256:1b1c214f6d9e22baff697500ee60fec4cd2f7b0d54c99e90a11c86af2e976b4c` |

The `0.4.3` tag names the same images. The service and Console images carry the label
`org.opencontainers.image.revision` set to
`source-144f4afa3671cb07972479225fab99a700dd2ce336ef0812af57937474f72c93`, and setup
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
  "image_revision": "source-144f4afa3671cb07972479225fab99a700dd2ce336ef0812af57937474f72c93",
  "service_image": "ghcr.io/lantern-networks/dsse-service@sha256:284d08999f8e7be0aec2d9f3551b2f61d87e7bf6fe98b838e29052beaf308697",
  "console_image": "ghcr.io/lantern-networks/dsse-console@sha256:ca50f7e44e24781c2e45be2bbb2939e7cdfece38d4deb9cc8d0fe67a1722365c",
  "data_layer": {
    "etcd_image": "ghcr.io/lantern-networks/dsse-etcd@sha256:3f195e59100f5bb515fa679ec422574f20f6cb4eda9860a818a80d19658e2197",
    "postgres_image": "ghcr.io/lantern-networks/dsse-postgres@sha256:110c4d06c377bfbdb7e69295186d13fd95626dc88b30d9b94c0ab8dd2f50df00",
    "postgres_tools_image": "ghcr.io/lantern-networks/dsse-postgres-tools@sha256:1b1c214f6d9e22baff697500ee60fec4cd2f7b0d54c99e90a11c86af2e976b4c",
    "postgres_major": 18
  }
}
```

The published images run on x86-64 (linux/amd64) hosts.

### Checking the packages

Check each package before installing it, in addition to `SHA256SUMS`:

- macOS: `pkgutil --check-signature LanternDsseAgent-0.4.3-20261115073439.pkg` reports
  `Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)` and
  `Notarization: trusted by the Apple notary service`, and
  `spctl -a -vvv -t install` on the package reports `accepted` with
  `source=Notarized Developer ID`.
- Windows: `Get-AuthenticodeSignature .\DsseAgent-0.4.3-windows-x64.msi` reports
  `Valid`, and the signer certificate's thumbprint is
  `0E10AB8EC192B4313E472A3CA0723B2D07123923`.

### Checking the images yourself

You can check the images with this repository and the registry alone:

- **Digest.** `docker pull` by the digests above, or `docker buildx imagetools
  inspect`, needs no sign-in. A digest names exactly one image.
- **Source.** The images, the installer binaries, the MSI and the PKG carry the content
  identity `source-144f4afa…` of the public commit `c06c2f619a995f789a5cfe1725649e1fb46af481`, which you can check
  from a clone:

  ```sh
  mkdir /tmp/dsse-0.4.3-source
  git archive c06c2f619a995f789a5cfe1725649e1fb46af481 | tar -x -C /tmp/dsse-0.4.3-source
  cd /tmp/dsse-0.4.3-source
  go run ./scripts/verify_source_content_id.go -root . \
    -expected source-144f4afa3671cb07972479225fab99a700dd2ce336ef0812af57937474f72c93
  ```

  `git diff c06c2f619a995f789a5cfe1725649e1fb46af481 v0.4.3-experimental` shows that the release tag adds only
  documentation.
- **Vulnerabilities.** Scan the same digests with your own scanner, for example
  `trivy image --platform linux/amd64 <image>@sha256:<digest>`. The release gate found no
  blocking high or critical finding; the one version-mapping exception is described in
  [Dependency versions](../../dependency-versions.md).

The images are not bit-for-bit reproducible: the service binaries embed their build
time, and the builds install the OS package updates current at build time. A rebuild
from the same commit has a different digest. It is not the verified release image:
generate its inventory and scan it before use.

`dsse-postgres` is built from Zalando Spilo on Ubuntu 22.04 with PostgreSQL 18.7,
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
