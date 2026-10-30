#!/usr/bin/env bash
# Build the 0.4.0 Spilo candidate from an exact upstream commit and reviewed patch.
# Usage: build_spilo_source.sh IMAGE_TAG [linux/amd64|linux/arm64]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo 'Usage: build_spilo_source.sh IMAGE_TAG [linux/amd64|linux/arm64]' >&2
    exit 2
fi
image_tag=$1
platform=${2:-linux/amd64}
case "$platform" in
    linux/amd64|linux/arm64) ;;
    *) echo 'Only linux/amd64 and linux/arm64 are supported' >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../deploy/spilo-4.1-p2.patch"
source_dir=$(mktemp -d "${TMPDIR:-/tmp}/dsse-spilo-source.XXXXXXXX")
walg_context=$(mktemp -d "${TMPDIR:-/tmp}/dsse-walg-context.XXXXXXXX")
trap 'rm -rf -- "$source_dir" "$walg_context"' EXIT

bash "$script_dir/build_walg_source.sh" "$walg_context" "$platform"

git clone --quiet --depth 1 --branch 4.1-p2 --filter=blob:none \
    https://github.com/zalando/spilo.git "$source_dir"
actual_commit=$(git -C "$source_dir" rev-parse HEAD)
expected_commit=550c5d8c183340ccd98b19098f53f1261b71539a
if [[ "$actual_commit" != "$expected_commit" ]]; then
    echo 'Spilo source commit mismatch' >&2
    exit 1
fi
git -C "$source_dir" apply --unidiff-zero --check "$patch_file"
git -C "$source_dir" apply --unidiff-zero "$patch_file"

docker buildx build --platform "$platform" \
    --build-arg PGVERSION=18 \
    --build-arg PGOLDVERSIONS= \
    --build-context "dsse_walg=$walg_context" \
    --file "$source_dir/postgres-appliance/Dockerfile" \
    --tag "$image_tag" --load "$source_dir/postgres-appliance"

docker run --rm --platform "$platform" --entrypoint /bin/bash "$image_tag" \
    -c 'set -euo pipefail; postgres --version | grep -F "PostgreSQL) 18.6"; patroni --version | grep -F "4.1.5"; wal-g --version'
docker run --rm --platform "$platform" --user postgres --entrypoint /bin/bash "$image_tag" \
    -c 'test -x /scripts/patroni_wait.sh && test -x /etc/runit/runsvdir/default/patroni/run && test -x /usr/local/bin/wal-g'
