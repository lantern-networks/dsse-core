# Dependency versions

This page lists the inputs this source selects. It says what is built from; it does not say
that an image built from these inputs has been scanned or run. The images each release
published, their digests, and what was scanned and accepted for them are in that release's
notes ([0.4.3](releases/0.4.3/README.md#server-container-images),
[0.4.2](releases/0.4.2/README.md#server-container-images),
[0.4.1](releases/0.4.1/README.md), [0.4.0](releases/0.4.0/README.md#server-container-images)).
The inputs below are those of the 0.4.3 release images. Scan results are recorded against
the digest that was scanned.
Release builds fix the source, Go modules, base images and native archives,
rather than resolving them at every build. The Go module manifests and native
archive checksums are the authoritative build inputs. The image builds also apply
the current OS package updates (`apk upgrade`, and `apt-get` in the Spilo build),
so a later rebuild can contain different OS packages. The published digests
identify the verified images; a rebuilt image needs its own inventory and scan.

| Component | Selected version | Source |
|---|---|---|
| Release Go toolchain | 1.27.4 | [Go downloads](https://go.dev/dl/) |
| Product/Console runtime base | Alpine 3.24.4, `sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf` | [Alpine releases](https://alpinelinux.org/releases/) |
| brotli (Go) | 1.3.0 | [Upstream](https://github.com/andybalholm/brotli) |
| klauspost/compress | 1.20.4 | [Release](https://github.com/klauspost/compress/releases/tag/v1.20.4) |
| lib/pq | 1.12.3 | [Releases](https://github.com/lib/pq/releases) |
| minio-go/v7 S3-compatible client SDK (not the MinIO server) | 7.4.1 | [Releases](https://github.com/minio/minio-go/releases) |
| golang.org/x/crypto | 0.59.0 | [Module](https://pkg.go.dev/golang.org/x/crypto@v0.59.0) |
| golang.org/x/net | 0.62.0 | [Module](https://pkg.go.dev/golang.org/x/net@v0.62.0) |
| golang.org/x/sys | 0.50.0 | [Module](https://pkg.go.dev/golang.org/x/sys@v0.50.0) |
| Additional Go updates | `cpuid/v2` 2.4.2, `go.yaml.in/yaml/v3` 3.0.6, `go-humanize` 1.1.0, `fwd` 1.2.1, `msgp` 1.6.5, `x/text` 0.44.0 | [go.mod](../go.mod) |
| Console TOTP QR generator | `qr` 0.7.2, vendored source SHA256 `3e3d38c37ecc5691b1edcc5b0dd6882b78280dc7f2130168bd7df074d1b21e47` | [Vendor notice](../console/vendor/README.md) |
| Windows MSI/Burn toolchain | WiX 7.0.1 with `wix7` OSMF EULA acceptance | [Build guide](../clients/windows-wfp/packaging/README.md) |
| GitHub Actions | checkout 7.0.1, setup-go 7.0.0, setup-node 7.1.0, upload-artifact 7.0.2 (commit-pinned) | [Workflow](../.github/workflows/ci.yml) |
| PostgreSQL privilege drop | Alpine `su-exec` 0.3-r0 in the derived PostgreSQL tools image; upstream `gosu` is removed | [Build recipe](../deploy/Dockerfile.postgres-tools) |
| etcd source and compiler | v3.7.3, commit `0a173d0410a96d01091b484daae81365bbcde57e`, Go 1.27.4, `x/net` 0.62.0 | [Build recipe](../deploy/Dockerfile.etcd) |
| Spilo source and HA dependencies | source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, PostgreSQL 18.7 target, Patroni 4.1.5, WAL-G 3.0.9 from commit `3e493188db28335fb93a45bd680c6ff8fc3028c1` with Go 1.27.4 and every module linked into it at its newest release, including `x/net` 0.62.0, gRPC 1.85.0, `go-jose` 4.1.8 (CVE-2026-116587 fixed from 4.1.6), `go.yaml.in/yaml/v3` 3.0.6 and `otelgrpc` 0.72.0; `pg_view` commit `3b35609f34b25db861252e2ce9912c2dab8a7934` | [Spilo source patch](../deploy/spilo-4.1-p2.patch), [WAL-G module patch](../deploy/wal-g-v3.0.9-go.patch), [Spilo build](../scripts/build_spilo_source.sh), [WAL-G build](../scripts/build_walg_source.sh) |

## Third-party image inputs

These are the default external images referenced by the generated deployment and
the Docker build recipes for distributed components. Digests are OCI index/manifest-list
digests where available.

| Purpose | Image reference | Status |
|---|---|---|
| HAProxy public and database entry | `haproxy:3.4.7-alpine3.24@sha256:b9fe316f718d5015c5cfebd8ca019591f3e44656f61d93cb8b59a1028961e530` | Digest fixed (upstream rebuilt 3.4.7; 3.4.7 is the newest 3.4 release). Scanned for 0.4.3 with no high or critical finding; ran in the 0.4.3 acceptance installations |
| ClickHouse | `clickhouse/clickhouse-server:26.8.37.168-alpine@sha256:1ce2d087a317a6e17369d2e358d496c04ba34cdf9f60593a85031218e98b60ff` | Updated to the newest 26.8 LTS patch. Scanned for 0.4.3 with no high or critical finding; ran in the 0.4.3 acceptance installations |
| PostgreSQL tools base | `postgres:18.7-alpine3.24@sha256:75dcac3dfb1cd01ca3536910bbc84128759362f8b118bf8c55b38a94f68f3b73` | Digest fixed. Its bundled `gosu` binary, which the derived image removes, is expected to carry scanner findings |
| PostgreSQL tools derived image | Builds from the pinned PostgreSQL base, removes `gosu`, uses `su-exec` | Published as `dsse-postgres-tools`. A release scans the image it publishes. No arm64 image is published |
| etcd source-built image | Builds from the pinned v3.7.3 commit with Go 1.27.4 and patched `x/net` | Published as `dsse-etcd`. A release scans the image it publishes. No arm64 image is published |
| Spilo/PostgreSQL runtime | Source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, Patroni 4.1.5, PostgreSQL 18.7 only, source-built WAL-G 3.0.9 | Published as `dsse-postgres`. A release scans the image it publishes, with the WAL-G exception below |
| Spilo source-build base | `ubuntu:22.04@sha256:74b12b11ffa550fba1929ad4d8d16533c34f6612728469671afba1b03b66881c` | Digest fixed, so the build installs the Ubuntu security updates current at that digest; obsolete Ubuntu 18.04 locale stage removed by the source patch |
| DSSE product and Admin Console runtime | Built from the pinned Go builder and Alpine runtime with host-platform compilation for each target architecture | Published as `dsse-service` and `dsse-console`. A release scans the images it publishes. No arm64 image is published |
| Product/Console builder | `golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf` | Digest fixed. Go 1.27.4 fixes GO-2026-6859 in `net/http` |

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
