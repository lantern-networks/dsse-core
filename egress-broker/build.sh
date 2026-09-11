#!/usr/bin/env bash
# build.sh — produce the egress-broker runtime image, end to end.
#
# WHY THIS EXISTS. This procedure lived in README.md as five prose steps, and the broker was the only component
# of the reference deployment not built by setup.sh. Two things followed from that, both observed:
#
#   * The README's own warning: step 4 "fails AFTER any earlier binary is already in place, so the stale
#     artifact gets packaged and the failure reads as a success." A warning is not a mechanism — so this script
#     DELETES the binary before rebuilding it, and a failed build can no longer ship a stale one.
#   * 2026-08-06: an AIA-chasing fix was written, the image was rebuilt, and the container was left stopped.
#     The Edge has no in-process fallback, so every bot-managed origin was failing while the fix sat in an
#     image nobody had started. Being part of setup.sh is what stops that recurring.
#
# Engine archives are cached by version and verified on every build. Matching library, CLI and headers
# are re-extracted from those verified archives before compiling; a stale version stamp is not trusted.
#
# Usage:  ./build.sh              # native arch (arm64 on Apple silicon)
#         ARCH=amd64 ./build.sh
#         ENGINE_VERSION=<version> ENGINE_CHECKSUMS=<reviewed-pins> ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

ENGINE_VERSION="${ENGINE_VERSION:-v2.2.2}"
case "${ARCH:-$(uname -m)}" in
  arm64|aarch64) ARCH=arm64; LIBDIR=cgo-arm64; BIN=egress-broker-cgo; DOCKERFILE=Dockerfile.runtime ;;
  amd64|x86_64) ARCH=amd64; LIBDIR=cgo-amd64; BIN=egress-broker-amd64; DOCKERFILE=Dockerfile.runtime.amd64 ;;
  *) echo "build.sh: unsupported architecture" >&2; exit 1 ;;
esac
IMAGE="${IMAGE:-dsse-egress-broker:$ARCH}"
ARCH="$ARCH" ENGINE_VERSION="$ENGINE_VERSION" bash ./fetch_engine.sh
builder="${DSSE_GO_BUILDER_IMAGE:-golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b}"

if [ -n "${DSSE_GO_BUILDER_IMAGE:-}" ]; then
  expected="${DSSE_GO_BUILDER_IMAGE_ID:-}"
  [[ "$expected" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'builder override requires DSSE_GO_BUILDER_IMAGE_ID' >&2; exit 1; }
  actual="$(docker image inspect --format '{{.Id}}' "$builder")"
  [ "$actual" = "$expected" ] || { echo 'builder image ID mismatch' >&2; exit 1; }
  builder="$expected"
fi
root="${DSSE_INSPECTION_ROOT:-/Library/Application Support/Dsse/interception-root.pem}"
if [ -f "$root" ]; then cp "$root" .build-inspection-root.pem
else : > .build-inspection-root.pem; fi
trap 'rm -f .build-inspection-root.pem' EXIT

# --- 4. the broker binary (cgo, against the engine lib) ---------------------------------------------------
# DELETE FIRST. This is the README's observed failure made impossible: with the old binary still in place, a
# failed compile left it for step 5 to package, and the whole run reported success while shipping stale code.
rm -f "$BIN"
echo "==> building $BIN (cgo)"
# Mount the OSS tree, not just this directory: the module depends on dsse-core via `replace => ..`, which
# resolves outside here. Mounting only this directory fails with "reading /go.mod: no such file".
docker run --rm --platform "linux/$ARCH" -v "$PWD/..:/oss" -w /oss/egress-broker \
  -v "$PWD/.build-inspection-root.pem:/usr/local/share/ca-certificates/dsse-build-inspection.crt:ro" \
  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local \
  -e CGO_CFLAGS="-I/oss/egress-broker/cgo-deps/include" \
  -e CGO_LDFLAGS="-L/oss/egress-broker/$LIBDIR -lcurl-impersonate" \
  "$builder" sh -ec 'update-ca-certificates >/dev/null; [ "$(go env GOVERSION)" = go1.27.1 ]; go build -trimpath -o "$1" .' sh "$BIN"
[ -s "$BIN" ] || { echo "build.sh: $BIN missing or empty after a build that reported success" >&2; exit 1; }

# --- 5. the runtime image ---------------------------------------------------------------------------------
echo "==> packaging $IMAGE"
docker build -q -f "$DOCKERFILE" -t "$IMAGE" . >/dev/null

# Say what was produced. The failure this script exists to prevent is a rebuild that nobody can tell happened.
echo "==> egress-broker image ready: $IMAGE ($(docker image inspect "$IMAGE" --format '{{.Id}}' | cut -c8-19), engine $ENGINE_VERSION)"
echo "    the running container is NOT restarted here — 'docker compose up -d egress-broker' does that."
