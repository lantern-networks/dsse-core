#!/usr/bin/env bash
# Fetch matching library, headers and CLI from an authenticated, checksum-pinned release.
set -euo pipefail
cd "$(dirname "$0")"
ENGINE_VERSION="${ENGINE_VERSION:-v2.2.2}"
checksums="${ENGINE_CHECKSUMS:-$PWD/engine-checksums.sha256}"
case "${ARCH:-$(uname -m)}" in
  arm64|aarch64) ARCH=arm64; triple=aarch64-linux-gnu; cli=cli ;;
  amd64|x86_64) ARCH=amd64; triple=x86_64-linux-gnu; cli=cli-amd64 ;;
  *) echo 'fetch_engine: unsupported architecture' >&2; exit 1 ;;
esac
cache="${ENGINE_DOWNLOAD_CACHE:-$PWD/.engine-downloads}"
mkdir -p "$cache"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
hash_file() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
for kind in libcurl curl; do
  name="$kind-impersonate-$ENGINE_VERSION.$triple.tar.gz"
  expected="$(awk -v name="$name" '$2 == name { print $1 }' "$checksums")"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "fetch_engine: no unique SHA-256 pin for $name" >&2; exit 1; }
  archive="$cache/$name"
  if [ ! -f "$archive" ]; then
    curl --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 -fsSL \
      "https://github.com/lexiforest/curl-impersonate/releases/download/$ENGINE_VERSION/$name" -o "$tmp/download"
    [ "$(hash_file "$tmp/download")" = "$expected" ] || { echo "fetch_engine: checksum mismatch: $name" >&2; exit 1; }
    mv "$tmp/download" "$archive"
  fi
  [ "$(hash_file "$archive")" = "$expected" ] || { echo "fetch_engine: cached checksum mismatch: $name" >&2; exit 1; }
  mkdir "$tmp/$kind"
  tar xzf "$archive" -C "$tmp/$kind"
done
[ -f "$tmp/libcurl/include/curl/curl.h" ] && [ -f "$tmp/libcurl/libcurl-impersonate.so.4.8.0" ] || {
  echo 'fetch_engine: release lacks matching headers/library' >&2; exit 1;
}
[ -f "$tmp/curl/curl_chrome146" ] && [ -f "$tmp/libcurl/LICENSE" ] || {
  echo 'fetch_engine: release lacks the selected profile or licence notices' >&2; exit 1;
}
# Re-extract verified inputs on every build. A version stamp cannot detect modified cached libraries.
rm -rf "cgo-$ARCH" "$cli" cgo-deps
mv "$tmp/libcurl" "cgo-$ARCH"
mv "$tmp/curl" "$cli"
mkdir -p cgo-deps/include
cp -R "cgo-$ARCH/include/curl" cgo-deps/include/
printf '%s %s\n' "$ENGINE_VERSION" "$ARCH" > .engine-version
echo "fetch_engine: verified $ENGINE_VERSION ($ARCH), matching headers and notices"
