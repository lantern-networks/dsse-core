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

date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Review candidates come from a history-free OSS export. The caller supplies the
# content manifest's identity, never the private repository's Git revision. Do
# not silently stamp the private parent repository when the export lives beneath it.
if [ -n "${DSSE_SOURCE_CONTENT_ID:-}" ]; then
	suffix="${DSSE_SOURCE_CONTENT_ID#source-}"
	case "$suffix" in
	# Enumerate ASCII digits: a range follows the caller's locale collation.
	*[!0123456789abcdef]*|'') valid_suffix=false ;;
	*) valid_suffix=true ;;
	esac
	if [ "$suffix" = "$DSSE_SOURCE_CONTENT_ID" ] || [ "${#suffix}" -ne 64 ] || [ "$valid_suffix" != true ]; then
		echo 'build_stamp: DSSE_SOURCE_CONTENT_ID must be source- followed by 64 lowercase hexadecimal characters' >&2
		exit 1
	fi
	commit="$DSSE_SOURCE_CONTENT_ID"
	dirty=false
else
	# A standalone Git checkout retains the existing development stamp. A Gitless
	# export requires its explicit content ID, even when Git finds a private parent.
	if [ ! -e "$root/.git" ]; then
		echo 'build_stamp: Gitless OSS export requires DSSE_SOURCE_CONTENT_ID' >&2
		exit 1
	fi
	commit="$(git -C "$root" rev-parse --short HEAD 2>/dev/null)" || {
		echo 'build_stamp: cannot identify the OSS Git checkout' >&2
		exit 1
	}
	# Dirty = tracked files modified. Untracked files do NOT count: this repo
	# always carries scratch tooling, which is not part of its Git revision.
	dirty=false
	if ! git -C "$root" diff --quiet 2>/dev/null || ! git -C "$root" diff --cached --quiet 2>/dev/null; then
		dirty=true
	fi
fi

printf -- '-X main.buildVersion=%s -X main.buildCommit=%s -X main.buildDate=%s -X main.buildDirty=%s\n' \
	"$version" "$commit" "$date" "$dirty"
