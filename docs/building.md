# Building

Run these commands at the root of a checkout of `dsse-core`. For a complete installation,
start with [Deployment](deployment.md); this page describes the build inputs and outputs.

## Prerequisites

- Git and a patched Go toolchain. The language minimum in [go.mod](../go.mod) is
  Go 1.26; use Go 1.27.1 for the release build. Set `GOTOOLCHAIN=go1.27.1` for the
  commands below so an older local toolchain does not reintroduce fixed standard-library vulnerabilities.
- Docker with the Compose v2 plugin for deployment images. Build Linux images matching
  the nodes' CPU architecture, either on a matching host or with a configured cross-build runtime.
- Access to the Go module proxy and the base-image registries while building.

Endpoint packaging has additional prerequisites described below. A service-image build
does not produce signed endpoint installers.

## Build the service images

```sh
docker build --build-arg DSSE_REVISION="$(git rev-parse --short HEAD)" \
  -f deploy/Dockerfile -t dsse:release .
docker build --build-arg DSSE_REVISION="$(git rev-parse --short HEAD)" \
  -f deploy/Dockerfile.console -t dsse-console:release .
```

Use a clean checkout of the selected release revision. `DSSE_REVISION` stamps the binaries
so `dsse-install -verify` can compare the fleet. For a source archive, pass the exact commit
identified by the release in place of `git rev-parse`; `unknown` cannot identify a build.

The generated `deployment.env` selects `DSSE_IMAGE=dsse:release` and
`DSSE_CONSOLE_IMAGE=dsse-console:release`. If using a registry, set **both** to the intended
image references, preferably immutable digests, on every node before starting Compose.

For nodes with the same architecture, build once and copy both images:

```sh
docker save -o dsse-images.tar dsse:release dsse-console:release
# Copy dsse-images.tar to each node, then run there:
docker load -i dsse-images.tar
```

`dsse-install -carry` packages configuration and credentials; it does **not** carry images.
Compose also uses third-party service images. Preload those as well if the nodes cannot
reach their registries. Inspect the generated Compose configuration for their exact references.

For the native curl-impersonate upstream transport, follow the separate
[egress broker build and integration guide](../egress-broker/README.md). The two builds
above do not compile that nested native module.

## Build operator tools and native binaries

```sh
export GOTOOLCHAIN=go1.27.1
mkdir -p bin
go build -o bin/dsse-install ./cmd/dsse-install
go build -o bin/dsse-profileverify ./cmd/dsse-profileverify
go build -o bin/dsse-signupdate ./cmd/dsse-signupdate
export PATH="$PWD/bin:$PATH"
```

These binaries target the machine running `go build`. Use the corresponding Linux
architecture when building binaries to copy to a deployment host. `go build ./...` builds
the main module; see [CONTRIBUTING.md](../CONTRIBUTING.md) for checks.

## Windows packages

Build on Windows with Go, a .NET SDK, WiX 5, and the Windows SDK signing tools. Driver
source builds also need the WDK. See the [packaging guide](../clients/windows-wfp/packaging/README.md)
for the actual commands and [Windows installation](windows-agent.md) for provisioning.

A locally test-signed driver is for a dedicated development machine. It does not provide
a driver accepted under normal Secure Boot policy. Supply a Microsoft-signed driver with
`-DriverSys` and select `-DriverAttested` for the attestation path. Signing the MSI alone
does not sign the driver. Consult Microsoft's [driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
for account and certificate prerequisites; signing is separate from compatibility testing.

## macOS packages

A Swift build alone is not an installable Network Extension. Packaging needs macOS,
a Swift 6 toolchain, app and extension provisioning profiles, matching signing keys,
and a Developer ID Installer identity and notarization credentials for distribution.
Supply your own profiles explicitly on a clean build machine; the scripts' installed-app
fallback is not a prerequisite you can rely on. See [Building the package](macos-agent.md#building-the-package).

## Container network conflicts

The generated network defaults to IPv4 `10.77.0.0/16` and an IPv6 ULA range. If another
network on the same host overlaps, change the related values together in `deployment.env`
before first startup, for example:

```sh
DSSE_SUBNET=10.78.0.0/16
DSSE_SUBNET_RANGE=10.78.1.0/24
DSSE_SUBNET_V6=fd00:d55e:78::/64
DSSE_FRONT_DOOR_A=10.78.0.5
DSSE_TRUSTED_FRONT_DOORS=10.78.0.5
```

The front door has a fixed address because Edges restrict which peers may supply a
PROXY protocol header. Update any diagnostic `--add-host` arguments to match it.

Release image builds pin Go 1.27.1. For matching local builds, set `GOTOOLCHAIN=go1.27.1` before running the Go commands.
