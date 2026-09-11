#!/bin/sh
# Emit the -ldflags value that stamps build identity into a Go binary. ONE place, so every build path
# (reference setup.sh, release builds, ad-hoc) stamps the same way and a binary can always answer "what am I?".
#
#   go build -ldflags "$(sh scripts/build_stamp.sh)" ./cmd/edge/
#   sh scripts/build_stamp.sh --version    # just the version string, for non-Go artifacts (.pkg, MSI)
#
# The version comes from the repo-root VERSION file — the single source of truth. Before this, "0.1.0" was
# written independently in the Windows WiX files and the macOS build scripts, with nothing keeping them equal.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(tr -d ' \n' < "$root/VERSION")"

if [ "${1:-}" = "--version" ]; then
	printf '%s\n' "$version"
	exit 0
fi

commit="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Dirty = tracked files modified. Untracked files do NOT count: this repo always carries some scratch tooling,
# and treating that as dirty would mark every build unreproducible and make the flag meaningless.
dirty=false
if ! git -C "$root" diff --quiet 2>/dev/null || ! git -C "$root" diff --cached --quiet 2>/dev/null; then
	dirty=true
fi

printf -- '-X main.buildVersion=%s -X main.buildCommit=%s -X main.buildDate=%s -X main.buildDirty=%s\n' \
	"$version" "$commit" "$date" "$dirty"
