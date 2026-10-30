#!/usr/bin/env bash
# Build the PostgreSQL WAL-G binary from a fixed release source and reviewed Go modules.
# Usage: build_walg_source.sh OUTPUT_DIRECTORY [linux/amd64|linux/arm64]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo 'Usage: build_walg_source.sh OUTPUT_DIRECTORY [linux/amd64|linux/arm64]' >&2
    exit 2
fi
output_dir=$1
platform=${2:-linux/amd64}
case "$platform" in
    linux/amd64) architecture=amd64 ;;
    linux/arm64) architecture=arm64 ;;
    *) echo 'Only linux/amd64 and linux/arm64 are supported' >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../deploy/wal-g-v3.0.9-go.patch"
otel_patch_file="$script_dir/../deploy/wal-g-v3.0.9-otel.patch"
source_dir=$(mktemp -d "${TMPDIR:-/tmp}/dsse-walg-source.XXXXXXXX")
trap 'rm -rf -- "$source_dir"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch v3.0.9 --filter=blob:none \
    https://github.com/wal-g/wal-g.git "$source_dir"
expected_commit=3e493188db28335fb93a45bd680c6ff8fc3028c1
if [[ $(git -C "$source_dir" rev-parse HEAD) != "$expected_commit" ]]; then
    echo 'WAL-G source commit mismatch' >&2
    exit 1
fi
git -C "$source_dir" apply --check "$patch_file"
git -C "$source_dir" apply "$patch_file"
git -C "$source_dir" apply --check "$otel_patch_file"
git -C "$source_dir" apply "$otel_patch_file"

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
(
    cd "$source_dir"
    GOTOOLCHAIN=go1.27.3 GOEXPERIMENT=jsonv2 GOOS=linux GOARCH="$architecture" CGO_ENABLED=0 \
      go build -mod=readonly -trimpath \
      -ldflags "-s -w -X github.com/wal-g/wal-g/cmd/pg.walgVersion=v3.0.9-dsse -X github.com/wal-g/wal-g/cmd/pg.gitRevision=$expected_commit" \
      -o "$output_dir/wal-g" ./main/pg
)
chmod 0755 "$output_dir/wal-g"

build_info=$(GOTOOLCHAIN=go1.27.3 go version -m "$output_dir/wal-g")
grep -Fq 'go1.27.3' <<< "$build_info"
grep -Eq 'golang.org/x/net[[:space:]]+v0\.61\.0' <<< "$build_info"
grep -Eq 'google.golang.org/grpc[[:space:]]+v1\.84\.0' <<< "$build_info"
grep -Eq 'go.opentelemetry.io/otel/sdk[[:space:]]+v1\.47\.0' <<< "$build_info"
echo "WAL-G v3.0.9 built from pinned source with Go 1.27.3 for $platform"
