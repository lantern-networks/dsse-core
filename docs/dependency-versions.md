# Dependency versions

Reviewed on 2026-09-09. Release builds use fixed versions, rather than resolving a
new dependency at every build. The Go module manifests and native archive checksums
are the authoritative build inputs.

| Component | Selected version | Source |
|---|---|---|
| Release Go toolchain | 1.27.1 | [Go downloads](https://go.dev/dl/) |
| Product/Console runtime base | Alpine 3.24.1 | [Alpine releases](https://alpinelinux.org/releases/) |
| curl-impersonate | 2.2.2, Chrome 146 profile | [Upstream release](https://github.com/lexiforest/curl-impersonate/releases/tag/v2.2.2) |
| Egress broker runtime base | Debian 13 (trixie-slim), pinned image digest | [Debian releases](https://www.debian.org/releases/) |
| brotli (Go) | 1.2.3 | [Upstream](https://github.com/andybalholm/brotli) |
| klauspost/compress | 1.20.0 | [Release](https://github.com/klauspost/compress/releases/tag/v1.20.0) |
| lib/pq | 1.12.3 | [Releases](https://github.com/lib/pq/releases) |
| minio-go/v7 | 7.3.0 | [Releases](https://github.com/minio/minio-go/releases) |
| golang.org/x/crypto | 0.57.0 | [Module](https://pkg.go.dev/golang.org/x/crypto@v0.57.0) |
| golang.org/x/net | 0.59.0 | [Module](https://pkg.go.dev/golang.org/x/net@v0.59.0) |
| golang.org/x/sys | 0.48.0 | [Module](https://pkg.go.dev/golang.org/x/sys@v0.48.0) |

Indirect requirements are also fixed in [go.mod](../go.mod), with integrity data in
`go.sum`. The minimum supported Go version is 1.26; using the pinned release toolchain
keeps compiler and standard-library versions consistent with the release build.

The native engine has its own dependencies, including BoringSSL and HTTP/3 libraries.
They are supplied together by curl-impersonate; a Go-only vulnerability scan does not
cover them. See the [native inventory](../egress-broker/THIRD-PARTY.md) and
[archive checksums](../egress-broker/engine-checksums.sha256).

Changing these versions does not enable an egress mode or change a running deployment.
The [broker guide](../egress-broker/README.md) describes the separate native build.
Database and other stateful service image settings remain deployment-specific; follow
their supported upgrade procedures before replacing existing data-bearing containers.
