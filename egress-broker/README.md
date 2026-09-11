# Egress broker

The broker re-originates intercepted HTTP requests through curl-impersonate, using
BoringSSL and a browser-compatible HTTP/2 profile. The Edge performs inspection and
policy evaluation; this component implements the upstream transport. Compatibility
with individual origin sites must be tested; a profile name is not a guarantee that
every site will treat a request as a browser.

## Deployment scope

**The standard `dsse-install` Compose deployment does not include or enable the broker.**
The Edge's `-swg-egress-browser-mimic` flag defaults to false. For that optional mode,
provide a running broker and `EGRESS_BROKER_URL`; an enabled broker path has no silent
fallback when the broker fails. Its health contributes to the Edge's readiness.

This page builds the component. Integrating it into a deployment requires configuring
its service, internal network reachability, and the Edge option/environment together.
The published installer does not currently generate that integration. Do not assume
that building its image enables browser-compatible egress in a running deployment.

The regular [deployment guide](../docs/deployment.md) covers the generated stack.

## Build

Requirements: Docker, network access to the pinned upstream engine release and Go modules,
and a Linux build runtime matching the intended architecture. From the public repository root:

```sh
cd egress-broker
./build.sh
```

The default image name is `dsse-egress-broker:<arch>`. The script supports `ARCH`,
`ENGINE_VERSION`, `ENGINE_CHECKSUMS`, and `IMAGE` overrides; use an appropriately configured build runtime
for the selected architecture. Selecting `ARCH` does not by itself configure a C cross-compiler.
For example, on a matching x86_64 runtime:

```sh
ARCH=amd64 ./build.sh
```

The default engine is **v2.2.2**. Both Linux architectures are pinned by SHA-256 in
`engine-checksums.sha256`, using the upstream release asset digests. An engine override
requires matching, independently reviewed checksums; floating headers are never used.
The Chrome 146 profile is retained to keep the existing wire behaviour.

The script fetches the native library, headers, and CLI, compiles the Go broker through
cgo, and packages its runtime image. Those downloaded and generated artifacts are
ignored by Git. A rebuild does not restart an existing container: deploy the selected
image explicitly and check the running container's image ID and startup log.

The engine is a **nested Go module** with a local dependency on the parent module.
The script mounts both; mounting only this directory into a Go build container cannot
resolve that dependency. The parent module's `go build ./...` does not build the broker.

Native-library licence notices and distribution requirements are in
[THIRD-PARTY.md](THIRD-PARTY.md). Check them when building or redistributing a different
engine version; Go-module inventories do not cover native linked dependencies.

## Runtime interface

| Route | Purpose |
|---|---|
| `POST /v1/reoriginate` | HTTP re-origination; request URL, method, and headers supplied by the Edge |
| `POST /v1/ws` | WebSocket transport |
| `GET /healthz` | Broker health |

The interface uses h2c. Keep it on the deployment's restricted internal network; it is
not an Internet-facing entry point. Only the intended Edges should reach it.

| Setting | Meaning |
|---|---|
| `EGRESS_BROKER_LISTEN` | Broker listen address, default `:8088` |
| `EGRESS_IMPERSONATE_BIN` | Engine profile/CLI name, default `curl_chrome146` |
| `EGRESS_BROKER_URL` | Edge-side URL of the broker |

Check the running broker's startup log for the selected profile and verify the engine's
available targets rather than inferring them from the library version. The upstream is
[lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate).

Requests for destinations served by a live DSSE connector use that connector's tunnel;
they must not be converted into direct broker connections into private address space.

## Embedded engine

`engine/` is also importable by the Edge with `-tags embedbroker`. This is a separate
cgo/native-library build, not the standard static image. In a prepared Linux build
environment, from the parent repository root, the command shape is:

```sh
CGO_ENABLED=1 CGO_CFLAGS="-I<absolute-engine-include-directory>" \
  CGO_LDFLAGS="-L<absolute-engine-library-directory> -lcurl-impersonate" \
  go build -tags embedbroker -o dsse-edge ./cmd/dsse-edge
```

The resulting binary needs its native runtime libraries and an appropriate runtime
image. The embedded transport tests live in `egressbroker/transport_embedded_test.go`
in the parent module. Test actual upstream requests and failures with the selected build;
a successful compilation alone does not establish a usable deployment integration.

The build uses Go 1.27.1. On an inspected build host, set `DSSE_INSPECTION_ROOT` to its CA PEM (the macOS agent path is detected automatically). This root is used for build-time downloads and removed from the runtime trust bundle. A local builder override requires its verified `DSSE_GO_BUILDER_IMAGE_ID`.
