#!/bin/sh
# Build dsse-install for a release: both Linux architectures, static, stamped with the version.
#
#   sh scripts/build_installer_release.sh OUTDIR
#
# The installer is what an operator runs first, on a machine that has Docker and nothing else. Shipping it built
# means that machine needs no Go toolchain and no clone of the source.
set -eu
out="${1:?usage: build_installer_release.sh OUTDIR}"
root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(sh "$root/scripts/build_stamp.sh" --version)"
# Taken first and on its own line, so a stamp that cannot be made stops the build instead of producing a binary
# that cannot say what it is.
stamp="$(sh "$root/scripts/build_stamp.sh")"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$root"
for arch in amd64 arm64; do
	name="dsse-install-$version-linux-$arch"
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -buildvcs=false -trimpath \
		-ldflags "$stamp" -o "$out/$name" ./cmd/dsse-install
	echo "built $name"
done
cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum dsse-install-"$version"-linux-* > dsse-install-"$version"-SHA256SUMS
else
	shasum -a 256 dsse-install-"$version"-linux-* > dsse-install-"$version"-SHA256SUMS
fi
cat dsse-install-"$version"-SHA256SUMS
