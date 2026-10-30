# Dependency versions

Reviewed on 2026-10-19. This table is not a completed 0.4.0 dependency acceptance:
the final multi-architecture registry digests and full image vulnerability gate remain pending.
Release builds use fixed
versions, rather than resolving a new dependency at every build. The Go module
manifests and native archive checksums are the authoritative build inputs.

| Component | Selected version | Source |
|---|---|---|
| Release Go toolchain | 1.27.3 | [Go downloads](https://go.dev/dl/) |
| Product/Console runtime base | Alpine 3.24.2, `sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6` | [Alpine releases](https://alpinelinux.org/releases/) |
| brotli (Go) | 1.2.6 | [Upstream](https://github.com/andybalholm/brotli) |
| klauspost/compress | 1.20.3 | [Release](https://github.com/klauspost/compress/releases/tag/v1.20.3) |
| lib/pq | 1.12.3 | [Releases](https://github.com/lib/pq/releases) |
| minio-go/v7 S3-compatible client SDK (not the MinIO server) | 7.4.1 | [Releases](https://github.com/minio/minio-go/releases) |
| golang.org/x/crypto | 0.58.0 | [Module](https://pkg.go.dev/golang.org/x/crypto@v0.58.0) |
| golang.org/x/net | 0.61.0 | [Module](https://pkg.go.dev/golang.org/x/net@v0.61.0) |
| golang.org/x/sys | 0.49.0 | [Module](https://pkg.go.dev/golang.org/x/sys@v0.49.0) |
| Additional Go updates | `cpuid/v2` 2.4.1, `go-humanize` 1.1.0, `fwd` 1.2.1, `msgp` 1.6.5, `x/text` 0.43.0 | [go.mod](../go.mod) |
| Console TOTP QR generator | `qr` 0.7.2, vendored source SHA256 `3e3d38c37ecc5691b1edcc5b0dd6882b78280dc7f2130168bd7df074d1b21e47` | [Vendor notice](../console/vendor/README.md) |
| Windows MSI/Burn toolchain | WiX 7.0.0 with `wix7` OSMF EULA acceptance | [Build guide](../clients/windows-wfp/packaging/README.md) |
| GitHub Actions | checkout 7.0.1, setup-go 7.0.0, setup-node 7.1.0, upload-artifact 7.0.2 (commit-pinned) | [Workflow](../.github/workflows/ci.yml) |
| PostgreSQL privilege drop | Alpine `su-exec` 0.3-r0 in the derived PostgreSQL tools image; upstream `gosu` is removed | [Build recipe](../deploy/Dockerfile.postgres-tools) |
| etcd source and compiler | v3.7.2, commit `68c065e562994b89e333e77b039ad066f933c586`, Go 1.27.3, `x/net` 0.61.0 | [Build recipe](../deploy/Dockerfile.etcd) |
| Spilo source and HA dependencies | source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, PostgreSQL 18.6 target, Patroni 4.1.5, WAL-G 3.0.9 from commit `3e493188db28335fb93a45bd680c6ff8fc3028c1` with Go 1.27.3, `x/net` 0.61.0, gRPC 1.84.0 and `go-jose` 4.1.6 (CVE-2026-116587); `pg_view` commit `3b35609f34b25db861252e2ce9912c2dab8a7934` | [Spilo source patch](../deploy/spilo-4.1-p2.patch), [WAL-G module patch](../deploy/wal-g-v3.0.9-go.patch), [Spilo build](../scripts/build_spilo_source.sh), [WAL-G build](../scripts/build_walg_source.sh) |

## Third-party image inputs

These are the default external images referenced by the generated deployment and
the Docker build recipes for distributed components. Digests are OCI index/manifest-list
digests where available.

| Purpose | Image reference | Status |
|---|---|---|
| HAProxy public and database entry | `haproxy:3.4.7-alpine3.24@sha256:251da69821897ec8c4819f12b1babbc4b71f562943addc9b9eb14bb6ece40dc6` | Digest fixed; both architecture image scans found zero high/critical findings; local syntax and deployment acceptance pending |
| ClickHouse | `clickhouse/clickhouse-server:26.8.36.3-alpine@sha256:f5443f9ffa48f0154cdd50cab39fed732201762574a27f04f1f564bbba81832d` | Digest fixed; both architecture image scans found zero high/critical findings; deployment acceptance pending |
| etcd | `quay.io/coreos/etcd:v3.7.2@sha256:e9afa62b1e914f02db62e5c46a7a140d8cdf026f2ed888cab4e5a142ec4d06fd` | Digest fixed; scanner reports high-severity issues in bundled Go binaries |
| PostgreSQL initialization and CI | `postgres:18.6-alpine3.24@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873` | Digest fixed; scanner reports high/critical issues in bundled Go binary |
| PostgreSQL tools derived image | Builds from the pinned PostgreSQL base, removes `gosu`, uses `su-exec` | Local ARM64/AMD64 startup and SQL checks passed; private multi-architecture candidate digest exists and both image scans have zero blocking high/critical findings. Final release digest and real-Linux installation acceptance remain pending |
| etcd source-built image | Builds from the pinned v3.7.2 commit with Go 1.27.3 and patched `x/net` | Local ARM64/AMD64 health and key read/write checks passed; private multi-architecture candidate digest exists and both image scans have zero blocking high/critical findings. Final release digest and real-Linux installation acceptance remain pending |
| Spilo/PostgreSQL runtime | Source commit `550c5d8c183340ccd98b19098f53f1261b71539a`, Patroni 4.1.5, PostgreSQL 18.6 only, source-built WAL-G 3.0.9 | Local ARM64 two-member HA, promotion, rejoin and row persistence passed on the PostgreSQL-18-only candidate. WAL-G local backup and restore passed; its unsupported encryption-key setting failed closed. Local AMD64 startup and SQL write/read passed. A private multi-architecture candidate digest exists; each image scan has only the narrowly verified WAL-G version-mapping exception. Final release digest and real-Linux installation acceptance remain pending |
| Spilo source-build base | `ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11` | Digest fixed; updated 2026-10-29 so the build installs the current Ubuntu security updates (CVE-2026-111497 in `libbrotli1`, fixed in `1.0.9-2ubuntu0.1`); obsolete Ubuntu 18.04 locale stage removed by the source patch |

| DSSE product and Admin Console runtime | Built from the pinned Go builder and Alpine runtime with host-platform compilation for each target architecture | Private multi-architecture candidate digests exist and both architecture scans have zero high/critical findings. An emulated AMD64 product smoke test was intermittent; native AMD64 Linux, final release digests and deployed-package acceptance remain pending |
| Product/Console builder | `golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd` | Digest fixed; both architecture image scans found zero high/critical findings |

The selected Spilo source currently uses Ubuntu 22.04 as its base. Track an
upstream base-image migration before Ubuntu 22.04 standard support ends in
2027 ([Ubuntu release cycle](https://ubuntu.com/about/release-cycle)); a digest
pin and clean scan do not extend OS support.

The upstream PostgreSQL base has findings in the removed `gosu` binary; the
mandatory scan target is the derived, distributed tools image. An offline review
cohort passed the image scan; this does not approve its final release or actual installation.
The official WAL-G 3.0.9 binary bundled an older Go toolchain and modules, so
Spilo uses a fixed-source WAL-G rebuild. Trivy still identifies its own module
as a pseudo-version below 1.1 and reports CVE-2021-38599. The fixed source
tag [contains the upstream repair](https://github.com/wal-g/wal-g/compare/cadf598e1c2a345915a21a44518c5a4d5401e2e3...v3.0.9); the gate records a narrowly scoped version-mapping exception for this exact commit and binary. Every other finding blocks release.
For etcd, Spilo, and PostgreSQL tools, the gate rejects a scanned digest that
differs from either completed installation plan. Generated Compose sets
`PGVERSION` to 18 and rejects an omitted data-layer image reference. Before
release, both plans must select the final scanned digests without changing the
PostgreSQL major.
Run an image-level scanner against every third-party and built DSSE image at release
time; retain each image digest and finding record. The product source SBOM alone does
not cover image packages or native libraries.

Indirect requirements are also fixed in [go.mod](../go.mod), with integrity data in
`go.sum`. The minimum supported Go version is 1.26; using the pinned release toolchain
keeps compiler and standard-library versions consistent with the release build.

The experimental egress-broker source remains in the repository, but its native engine,
builder and runtime image are not part of the 0.4.0 distribution or its required image
scan. Browser-mimic mode is not qualified for this release. The standard Go upstream
path does not use those native libraries.

Changing these versions does not enable an egress mode or change a running deployment.
Database and other stateful service image settings remain deployment-specific; follow
their supported upgrade procedures before replacing existing data-bearing containers.
