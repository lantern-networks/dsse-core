# Building

Run these commands at the root of the selected `dsse-core` source directory. For a complete installation,
start with [Deployment](deployment.md); this page describes the build inputs and outputs.

## Prerequisites

- Git and a patched Go toolchain. The language minimum in [go.mod](../go.mod) is
  Go 1.26.9; use Go 1.27.3 for the release build. Set `GOTOOLCHAIN=go1.27.3` for the
  commands below so an older local toolchain does not reintroduce fixed standard-library vulnerabilities.
- Docker with the Compose v2 plugin for deployment images. Build Linux images matching
  the nodes' CPU architecture, either on a matching host or with a configured cross-build runtime.
- Access to the Go module proxy and the base-image registries while building.

Endpoint packaging has additional prerequisites described below. A service-image build
does not produce signed endpoint installers.

## Choose the source identity first

For a clean public Git checkout, set `DSSE_REVISION` to that public commit:

```sh
export DSSE_REVISION="$(git rev-parse HEAD)"
```

For a source archive, **do not run Git in or above the extracted directory**.
It has no Git history; an enclosing checkout can report an unrelated revision.
Set `DSSE_REVISION` to the exact public commit recorded with the archive, or the
`source-<content-sha256>` identity recorded in the release's `release-manifest.json`.
Use that same value as `image_revision` in the installation plan. Do not use
`unknown`, a private repository commit, or a new timestamp as source identity.

## Build the service images

```sh
docker build --build-arg DSSE_REVISION="${DSSE_REVISION:?set the reviewed source identity first}" \
  -f deploy/Dockerfile -t dsse:release .
docker build --build-arg DSSE_REVISION="${DSSE_REVISION:?set the reviewed source identity first}" \
  -f deploy/Dockerfile.console -t dsse-console:release .
```

Use the selected clean source. `DSSE_REVISION` stamps the service binaries and
both first-party images' OCI revision labels. Local `-preflight` compares those
labels, the actual service binary and the plan before startup; full `-verify`
compares the running fleet later. Matching labels alone do not attest image
provenance: build from the reviewed source and verify distribution hashes.

The generated `deployment.env` selects `DSSE_IMAGE=dsse:release` and
`DSSE_CONSOLE_IMAGE=dsse-console:release`. For a shared-fleet plan, set `service_image` and `console_image`
to the intended references (immutable registry digests, such as the published release images), and `image_revision`
to the source identity above. Generate each node from that complete plan; do not
hand-edit image references into generated files. Unspecified image references
retain the local tags above; `image_revision` is required by setup preflight.
The final image gate compares both completed supported installation plans with
the exact five scanned image digests; local tags are not release evidence.

Every PostgreSQL 18 installation plan must select one immutable data-layer
cohort before `-preflight` or `-start-node`. Use the images published with the
release (see the [0.4.0 release README](releases/0.4.0/README.md#server-container-images))
or images you built (see [Build the data-layer images](#build-the-data-layer-images)):

```json
"data_layer": {
  "etcd_image": "registry.example/etcd@sha256:<64 hex digits>",
  "postgres_image": "registry.example/spilo@sha256:<64 hex digits>",
  "postgres_tools_image": "registry.example/postgres-tools@sha256:<64 hex digits>",
  "postgres_major": 18
}
```

Replace these placeholders with the reviewed digests. The installer carries all
four settings to every node. Its generated Compose uses the same Spilo image for
the server and TLS init service, sets `PGVERSION=18`, and uses the selected
PostgreSQL tools image for database initialization. Local `-preflight` checks
the parsed service images and runs `postgres --version` from the selected Spilo
image with no network and a read-only filesystem; it refuses a major mismatch.
Preflight refuses a plan that omits `data_layer`. Generated Compose also refuses
to interpolate its etcd, Spilo, and PostgreSQL tools services without explicit
image references; it has no legacy fallback for these images. Use `-preflight`
and `-start-node` to check the actual image contents before starting services.
The published 0.4.0 images were installed fresh on Linux hosts in the three-Region
and one-Region layouts; see the release acceptance record for what each covered.

For nodes with the same architecture, build once and copy both first-party images:

```sh
docker save -o dsse-images.tar dsse:release dsse-console:release
# Copy dsse-images.tar to each node, then run there:
docker load -i dsse-images.tar
```

DSSE does not build or bundle an object-storage server. S3 archival is optional:
without an `archive` plan entry, aged hot events remain in the persistent local
store, whose capacity and backups the operator must manage. If archival is selected,
provision an external S3-compatible bucket before setup, enable versioning and
Object Lock, and declare its endpoint, bucket, region and authentication mode in
the plan. Static credentials belong only in each control plane's private
`deployment.env`; IAM workload identity is also supported. See [Deployment](deployment.md).

`dsse-install -carry` packages configuration and credentials; it does **not** carry images.
Compose also uses third-party service images. Preload those as well if the nodes cannot
reach their registries. Inspect the generated Compose configuration for their exact references.

For the native curl-impersonate upstream transport, follow the separate
[egress broker build and integration guide](../egress-broker/README.md). These service builds
do not compile that nested native module. The 0.4.0 release does not
include or qualify a broker executable or image.

### Build the data-layer images

The published images are linux/amd64 only. For arm64 hosts, or to rebuild them,
build the three data-layer images from the recipes in this repository for the
hosts' architecture. These are the commands the 0.4.0 release images were built with:

```sh
PLATFORM=linux/amd64   # or linux/arm64
docker buildx build --platform "$PLATFORM" -f deploy/Dockerfile.etcd -t dsse-etcd:local --load .
docker buildx build --platform "$PLATFORM" -f deploy/Dockerfile.postgres-tools -t dsse-postgres-tools:local --load .
bash scripts/build_spilo_source.sh dsse-postgres:local "$PLATFORM"
```

`build_spilo_source.sh` clones Spilo and WAL-G at fixed commits, applies
`deploy/spilo-4.1-p2.patch`, and checks the PostgreSQL, Patroni and WAL-G versions
in the result. The plan accepts only `name@sha256:<digest>` references for these
images, and a locally built image has no registry digest. Push the three images to
a registry every host can pull from, and put the digests the pushes print in
`data_layer`. Scan each image before use.

## Build operator tools and native binaries

```sh
export GOTOOLCHAIN=go1.27.3
mkdir -p bin
go build -buildvcs=false -trimpath -o bin/dsse-install ./cmd/dsse-install
go build -buildvcs=false -trimpath -o bin/dsse-profileverify ./cmd/dsse-profileverify
go build -buildvcs=false -trimpath -o bin/dsse-deployment-crl ./cmd/dsse-deployment-crl
go build -buildvcs=false -trimpath -o bin/dsse-signupdate ./cmd/dsse-signupdate
export PATH="$PWD/bin:$PATH"
```

These binaries target the machine running `go build`. The deployment CRL signer and
keyless publisher run on Linux hosts and require the reviewed Linux binary from the
same source as the installer; check its architecture and hash before installation.
Use the corresponding Linux architecture when building binaries to copy to a deployment host. `go build ./...` builds
the main module; see [CONTRIBUTING.md](../CONTRIBUTING.md) for checks.

## Windows packages

Build on Windows with Go, a .NET SDK, WiX 7.0.0, and the Windows SDK signing tools. Driver
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

The generated network defaults to IPv4 `10.77.0.0/16` and an IPv6 ULA range. The
ULA is internal container addressing, **not** proof of outbound IPv6. Select and
verify the [deployment address-family mode](deployment.md#choose-ipv4-only-or-dual-stack-before-enrolling-devices)
before installing endpoint agents. If another network on the same host overlaps,
change the related values together in `deployment.env` before first startup, for
example:

```sh
DSSE_SUBNET=10.78.0.0/16
DSSE_SUBNET_RANGE=10.78.1.0/24
DSSE_SUBNET_V6=fd00:d55e:78::/64
DSSE_FRONT_DOOR_A=10.78.0.5
DSSE_TRUSTED_FRONT_DOORS=10.78.0.5
```

The front door has a fixed address because Edges restrict which peers may supply a
PROXY protocol header. Update any diagnostic `--add-host` arguments to match it.

Release image builds pin Go 1.27.3. For matching local builds, set `GOTOOLCHAIN=go1.27.3` before running the Go commands.
