# Dependency versions

Updated for the 0.4.1 candidate (November 4, 2026). This page lists what the current
source selects. It does not carry over the 0.4.0 acceptance: a changed digest or version
has not run in an acceptance installation until the 0.4.1 release notes say it has. The
0.4.0 versions, published digests and scan results stay in the
[0.4.0 release README](releases/0.4.0/README.md#server-container-images). Scan results are
recorded against the digest that was scanned; the 0.4.1 release notes will name the final
digests and their scans.
Release builds fix the source, Go modules, base images and native archives,
rather than resolving them at every build. The Go module manifests and native
archive checksums are the authoritative build inputs. The image builds also apply
the current OS package updates (`apk upgrade`, and `apt-get` in the Spilo build),
so a later rebuild can contain different OS packages. The published digests
identify the verified images; a rebuilt image needs its own inventory and scan.

| Component | Selected version | Source |
|---|---|---|
| Release Go toolchain | 1.27.3 | [Go downloads](https://go.dev/dl/) |
| Product/Console runtime base | Alpine 3.24.3, `sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` | [Alpine releases](https://alpinelinux.org/releases/) |
| brotli (Go) | 1.2.7 | [Upstream](https://github.com/andybalholm/brotli) |
| klauspost/compress | 1.20.3 | [Release](https://github.com/klauspost/compress/releases/tag/v1.20.3) |
| lib/pq | 1.12.3 | [Releases](https://github.com/lib/pq/releases) |
| minio-go/v7 S3-compatible client SDK (not the MinIO server) | 7.4.1 | [Releases](https://github.com/minio/minio-go/releases) |
| golang.org/x/crypto | 0.58.1-0.20261009181718-2f1f834330b2 (pre-release revision; GO-2026-5932 is fixed there and v0.58.0 is the latest tag) | [Module](https://pkg.go.dev/golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2) |
| golang.org/x/net | 0.62.0 | [Module](https://pkg.go.dev/golang.org/x/net@v0.62.0) |
| golang.org/x/sys | 0.49.0 | [Module](https://pkg.go.dev/golang.org/x/sys@v0.49.0) |
| Additional Go updates | `cpuid/v2` 2.4.2, `go.yaml.in/yaml/v3` 3.0.6, `go-humanize` 1.1.0, `fwd` 1.2.1, `msgp` 1.6.5, `x/text` 0.43.0 | [go.mod](../go.mod) |
| Console TOTP QR generator | `qr` 0.7.2, vendored source SHA256 `3e3d38c37ecc5691b1edcc5b0dd6882b78280dc7f2130168bd7df074d1b21e47` | [Vendor notice](../console/vendor/README.md) |
| Windows MSI/Burn toolchain | WiX 7.0.1 with `wix7` OSMF EULA acceptance | [Build guide](../clients/windows-wfp/packaging/README.md) |
| GitHub Actions | checkout 7.0.1, setup-go 7.0.0, setup-node 7.1.0, upload-artifact 7.0.2 (commit-pinned) | [Workflow](../.github/workflows/ci.yml) |
| PostgreSQL privilege drop | Alpine `su-exec` 0.3-r0 in the derived PostgreSQL tools image; upstream `gosu` is removed | [Build recipe](../deploy/Dockerfile.postgres-tools) |
| etcd source and compiler | v3.7.3, commit `0a173d0410a96d01091b484daae81365bbcde57e`, Go 1.27.3, `x/net` 0.62.0 | [Build recipe](../deploy/Dockerfile.etcd) |
| Spilo source and HA dependencies | source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, PostgreSQL 18.6 target, Patroni 4.1.5, WAL-G 3.0.9 from commit `3e493188db28335fb93a45bd680c6ff8fc3028c1` with Go 1.27.3 and every module linked into it at its newest release, including `x/net` 0.62.0, gRPC 1.85.0, `go-jose` 4.1.8 (CVE-2026-116587 fixed from 4.1.6), `go.yaml.in/yaml/v3` 3.0.6 and `otelgrpc` 0.72.0; `pg_view` commit `3b35609f34b25db861252e2ce9912c2dab8a7934` | [Spilo source patch](../deploy/spilo-4.1-p2.patch), [WAL-G module patch](../deploy/wal-g-v3.0.9-go.patch), [Spilo build](../scripts/build_spilo_source.sh), [WAL-G build](../scripts/build_walg_source.sh) |

## Third-party image inputs

These are the default external images referenced by the generated deployment and
the Docker build recipes for distributed components. Digests are OCI index/manifest-list
digests where available.

| Purpose | Image reference | Status |
|---|---|---|
| HAProxy public and database entry | `haproxy:3.4.7-alpine3.24@sha256:2caaf8b1a1ef67f3f1ea9b721f2821675d3ba4500fb518e23884fecb93e8dbaa` | Digest fixed (upstream rebuilt 3.4.7 on Alpine 3.24.3; both child images changed). Scan and acceptance for 0.4.1 pending |
| ClickHouse | `clickhouse/clickhouse-server:26.8.36.3-alpine@sha256:f5443f9ffa48f0154cdd50cab39fed732201762574a27f04f1f564bbba81832d` | Unchanged from 0.4.0 (newest 26.8 LTS patch); ran in both 0.4.0 acceptance installations. Rescan for 0.4.1 pending |
| PostgreSQL tools base | `postgres:18.6-alpine3.24@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5` | Digest fixed (upstream rebuilt 18.6 on Alpine 3.24.3). Its bundled `gosu` binary, which the derived image removes, is expected to carry scanner findings |
| PostgreSQL tools derived image | Builds from the pinned PostgreSQL base, removes `gosu`, uses `su-exec` | Rebuilt for the 0.4.1 candidate on the new base. Scan and acceptance of the current candidate pending. No arm64 image is published |
| etcd source-built image | Builds from the pinned v3.7.3 commit with Go 1.27.3 and patched `x/net` | Rebuilt for the 0.4.1 candidate. Scan and acceptance of the current candidate pending. No arm64 image is published |
| Spilo/PostgreSQL runtime | Source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, Patroni 4.1.5, PostgreSQL 18.6 only, source-built WAL-G 3.0.9 | Rebuilt for the 0.4.1 candidate with the updated WAL-G. Scan and acceptance of the current candidate pending; failover and backup/restore on a published image remain open acceptance items |
| Spilo source-build base | `ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11` | Digest fixed; updated 2026-10-29 so the build installs the current Ubuntu security updates (CVE-2026-111497 in `libbrotli1`, fixed in `1.0.9-2ubuntu0.1`); obsolete Ubuntu 18.04 locale stage removed by the source patch |
| DSSE product and Admin Console runtime | Built from the pinned Go builder and Alpine runtime with host-platform compilation for each target architecture | Rebuilt for the 0.4.1 candidate. Scan and acceptance of the current candidate pending. No arm64 image is published |
| Product/Console builder | `golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb` | Digest fixed (upstream rebuilt on Alpine 3.24.3). Rescan for 0.4.1 pending |

The selected Spilo source currently uses Ubuntu 22.04 as its base. Track an
upstream base-image migration before Ubuntu 22.04 standard support ends in
2027 ([Ubuntu release cycle](https://ubuntu.com/about/release-cycle)); a digest
pin and clean scan do not extend OS support.

The upstream PostgreSQL base has findings in the removed `gosu` binary; the
mandatory scan target is the derived, distributed tools image, which must pass the release scan.
The official WAL-G 3.0.9 binary bundled an older Go toolchain and modules, so
Spilo uses a fixed-source WAL-G rebuild. Trivy still identifies its own module
as a pseudo-version below 1.1 and reports CVE-2021-38599. The fixed source
tag [contains the upstream repair](https://github.com/wal-g/wal-g/compare/cadf598e1c2a345915a21a44518c5a4d5401e2e3...v3.0.9); the gate records a narrowly scoped version-mapping exception for this exact commit and binary. Every other finding blocks release.
For etcd, Spilo, and PostgreSQL tools, the gate rejects a scanned digest that
differs from either completed installation plan. Generated Compose sets
`PGVERSION` to 18 and rejects an omitted data-layer image reference. Both 0.4.0
acceptance installations used the 0.4.0 published digests.
Run an image-level scanner against every third-party and built DSSE image at release
time; retain each image digest and finding record. The product source SBOM alone does
not cover image packages or native libraries.

Indirect requirements are also fixed in [go.mod](../go.mod), with integrity data in
`go.sum`. The minimum supported Go version is 1.26.9; using the pinned release toolchain
keeps compiler and standard-library versions consistent with the release build.

The experimental egress-broker source remains in the repository, but its native engine,
builder and runtime image are not part of the 0.4.0 or 0.4.1 distribution or its required image
scan. Browser-mimic mode is not qualified for this release. The standard Go upstream
path does not use those native libraries.

Changing these versions does not enable an egress mode or change a running deployment.
Database and other stateful service image settings remain deployment-specific; follow
their supported upgrade procedures before replacing existing data-bearing containers.
