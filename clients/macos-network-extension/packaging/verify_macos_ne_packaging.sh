#!/bin/sh
# Guard against the macOS NE "silent un-steer" failure class. Statically asserts that a packaged
# LanternDsseAgent.app is internally consistent enough that the agent WILL find and activate its embedded
# System Extension — so a bundle-id mismatch or a signing-metadata clobber can never again leave the agent
# running while all traffic flows un-intercepted.
#
# Background (2026-06-27): the agent derives its activation target at runtime as
#   Bundle.main.bundleIdentifier + ".networkextension"
# so the ONLY way activation can silently fail is if the packaged invariants below are violated:
#   1. app CFBundleIdentifier + ".networkextension" != embedded extension CFBundleIdentifier
#        -> the derived activation target names an extension that is not embedded -> activation fails.
#   2. codesign Identifier != CFBundleIdentifier (app or extension)
#        -> happens when re-signing with `--preserve-metadata=identifier` over a fresh ad-hoc build
#           (identifier becomes "DsseAgent-<hash>") -> the signed identity no longer matches the bundle.
#   3. missing / empty entitlements, or application-identifier entitlement not matching the bundle id
#        -> happens when `--preserve-metadata=entitlements` preserves the fresh build's (empty) entitlements
#           -> the NetworkExtension entitlement is gone -> activation is rejected.
# This script checks all three (plus codesign --verify) and fails closed.
#
# Usage:  sh deploy/reference/verify_macos_ne_packaging.sh [/path/to/LanternDsseAgent.app]
#         (defaults to the installed /Applications/LanternDsseAgent.app)
# Exit 0 only if every check passes; non-zero (with a specific reason) otherwise.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
app="${1:-${DSSE_AGENT_APP:-/Applications/LanternDsseAgent.app}}"
[ -d "$app" ] || { echo "FAIL: app bundle not found: $app"; exit 1; }

fail() { echo "FAIL: $1"; exit 1; }
ok() { echo "  ok: $1"; }

# Check mode bits, not access as the build owner: PackageKit changes ownership
# to root, and codesign/Gatekeeper accept an app that only root can read.
/usr/bin/python3 - "$app" <<'MODES' || fail "app bundle permissions prevent safe use by a standard user"
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for parent, dirs, files in os.walk(root):
    for path in [pathlib.Path(parent)] + [pathlib.Path(parent) / name for name in files]:
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        required = 0o555 if path.is_dir() or mode & 0o111 else 0o444
        if mode & required != required or mode & 0o022:
            print('Invalid app permissions: %s (%04o)' % (path.relative_to(root), mode))
            sys.exit(1)
MODES
ok "app resources remain readable and directories traversable after root ownership"

# --- locate the embedded extension ---
sysext="$(ls -d "$app/Contents/Library/SystemExtensions/"*.systemextension 2>/dev/null | head -1)"
[ -n "$sysext" ] && [ -d "$sysext" ] || fail "no embedded .systemextension under $app"

app_id="$(defaults read "$app/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)"
sysext_id="$(defaults read "$sysext/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)"
[ -n "$app_id" ] || fail "app CFBundleIdentifier missing"
[ -n "$sysext_id" ] || fail "extension CFBundleIdentifier missing"

echo "verify_macos_ne_packaging: app=$app_id ext=$sysext_id"

# --- check 1: derived activation target == embedded extension id ---
[ "${app_id}.networkextension" = "$sysext_id" ] \
	|| fail "bundle-id mismatch: agent will activate '${app_id}.networkextension' but the embedded extension is '$sysext_id'"
ok "agent's runtime-derived activation target matches the embedded extension id"

# --- check 2: codesign identity == bundle id (catches --preserve-metadata=identifier clobber) ---
signed_app_id="$(codesign -dv "$app" 2>&1 | sed -n 's/^Identifier=//p')"
signed_ext_id="$(codesign -dv "$sysext" 2>&1 | sed -n 's/^Identifier=//p')"
[ "$signed_app_id" = "$app_id" ] || fail "app signed identifier '$signed_app_id' != CFBundleIdentifier '$app_id' (preserve-metadata clobber?)"
[ "$signed_ext_id" = "$sysext_id" ] || fail "extension signed identifier '$signed_ext_id' != CFBundleIdentifier '$sysext_id' (preserve-metadata clobber?)"
ok "codesign identifiers match the bundle ids"

# --- check 3: entitlements present and application-identifier matches the bundle id ---
check_entitlement_app_id() {
	# $1 = mach-o binary, $2 = expected bundle id
	ents="$(codesign -d --entitlements :- "$1" 2>/dev/null || true)"
	case "$ents" in
		*com.apple.developer.networking.networkextension*) : ;;
		*) fail "missing NetworkExtension entitlement on $1 (entitlements lost in signing?)" ;;
	esac
	case "$ents" in
		*"<string>"*".$2</string>"* | *"<string>$2</string>"*) : ;;
		*) : ;;  # application-identifier carries a team prefix; the substring check below is the real gate
	esac
	case "$ents" in
		*"$2"*) : ;;
		*) fail "application bundle id '$2' not present in entitlements of $1" ;;
	esac
}
check_entitlement_app_id "$app/Contents/MacOS/$(defaults read "$app/Contents/Info.plist" CFBundleExecutable)" "$app_id"
check_entitlement_app_id "$sysext/Contents/MacOS/$(defaults read "$sysext/Contents/Info.plist" CFBundleExecutable)" "$sysext_id"
ok "entitlements present and reference the correct bundle ids"

# --- check 4: signatures structurally valid ---
codesign --verify --strict "$sysext" 2>/dev/null || fail "codesign --verify failed for the extension"
codesign --verify --strict "$app" 2>/dev/null || fail "codesign --verify failed for the app"
ok "codesign --verify passes for app and extension"

# --- check 5: the bundle agrees with the profile it ships ---
#
# Checks 1-4 ask whether the bundle is consistent WITH ITSELF. It can pass all four and still not activate,
# because the authority for the NetworkExtension entitlement lives in a document the bundle carries but does not
# have to agree with. Found on 2026-08-10 while moving to Developer ID: Development profiles grant
# "app-proxy-provider" and Developer ID profiles grant "app-proxy-provider-systemextension", exclusively, so a
# build that hardcoded either value produced — for the other profile — a bundle that passes every check above
# and whose extension the system refuses. Same silent-un-steer outcome, arriving from outside the bundle.
. "$(cd "$(dirname "$0")" && pwd)/lib_provisioning_profile.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check_bundle_profile() {
	# $1 = bundle dir, $2 = bundle id, $3 = label
	prof="$1/Contents/embedded.provisionprofile"
	[ -f "$prof" ] || fail "$3 has no embedded.provisionprofile — it will sign but NOT activate"
	dsse_profile_decode "$prof" "$tmp/$3.plist" || fail "$3 embedded.provisionprofile is not a provisioning profile"

	# The profile must be FOR this bundle. Embedding the app's profile in the extension is the easy mistake:
	# same basename, different document.
	got="$(dsse_profile_app_identifier "$tmp/$3.plist" || true)"
	case "$got" in
	*".$2") : ;;
	*) fail "$3 embeds a profile issued for '$got', not for '$2'" ;;
	esac

	# Signed entitlements must be a SUBSET of what the profile grants. Checked on the value that actually gates
	# activation rather than on the whole set, because that is the one that differs between profile kinds.
	granted="$(dsse_profile_ne_appproxy "$tmp/$3.plist" || true)"
	[ -n "$granted" ] || fail "$3 profile grants no App Proxy entitlement"
	signed="$(codesign -d --entitlements :- "$1" 2>/dev/null | tr -d ' \t\n' || true)"
	case "$signed" in
	*"<string>$granted</string>"*) : ;;
	*) fail "$3 is signed with an App Proxy entitlement the profile does not grant (profile grants '$granted') — this signs and verifies but will NOT activate" ;;
	esac

	# The leaf that signed it must be one the profile authorises. By FINGERPRINT: two identities in this
	# keychain differ only by the operator's name, so a name comparison would accept the wrong one.
	rm -f "$tmp/leaf"*
	codesign -d --extract-certificates="$tmp/leaf" "$1" 2>/dev/null || fail "$3 has no extractable signing certificate"
	leaf="$(shasum -a 1 "$tmp/leaf0" | cut -d' ' -f1 | tr 'a-z' 'A-Z')"
	n="$(plutil -extract DeveloperCertificates raw -o - "$tmp/$3.plist" 2>/dev/null || echo 0)"
	i=0
	found=0
	while [ "$i" -lt "$n" ]; do
		c="$(plutil -extract "DeveloperCertificates.$i" raw -o - "$tmp/$3.plist" | base64 -d | shasum -a 1 | cut -d' ' -f1 | tr 'a-z' 'A-Z')"
		[ "$c" = "$leaf" ] && found=1 && break
		i=$((i + 1))
	done
	[ "$found" = 1 ] || fail "$3 was signed by a certificate its own profile does not authorise"
}
check_bundle_profile "$app" "$app_id" "app"
check_bundle_profile "$sysext" "$sysext_id" "extension"

app_kind="$(dsse_profile_kind "$tmp/app.plist")"
[ "$app_kind" = "$(dsse_profile_kind "$tmp/extension.plist")" ] \
	|| fail "app and extension embed different KINDS of profile — one would run anywhere, the other only on registered Macs"
ok "profiles match their bundles, authorise the entitlements signed, and authorise the signing certificate ($app_kind)"

# ★★★ A BRAND ASSET THAT DRAWS NOTHING LOOKS EXACTLY LIKE ONE THAT DRAWS (2026-09-07, reported from the
# Windows side after it shipped a 512x512 PNG of 7KB with not one opaque pixel in it, in two trees, unnoticed
# for weeks). Every other check in this file reads a return code; this one has to read the PIXELS, because the
# failure it is looking for produces no error anywhere — the file opens, the image decodes, the size is right,
# and the window shows an empty box.
#
# ★★ THE FIRST VERSION OF THIS CHECK WAS ITSELF BROKEN, and by exactly the same kind of mistake. It counted
# every fourth byte of a `sips`-produced TIFF as an alpha channel; the header is not the eight bytes that
# assumed, so a fully transparent 512x512 PNG came back "667 visible pixels" and a fully opaque one came back
# 4763 of 4096. It was caught by feeding it two images whose answers were known in advance — which is the only
# way a counting check can be trusted, and is now how this one is exercised.
#
# ★ PYTHON IS ALLOWED TO BE ABSENT. A gate that cannot run must skip loudly rather than fail: a verifier that
# dies for an environment reason teaches people to stop running it, which switches off every check in this
# file and not only this one.
brand_png="$app/Contents/Resources/lantern-symbol.png"
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "" >/dev/null 2>&1; then
	echo "note: python3 is not usable here, so the brand asset was NOT measured — a transparent mark would pass unseen"
elif [ ! -f "$brand_png" ]; then
	echo "note: this bundle carries no step-up mark ($brand_png) — the window falls back to its wordmark alone"
else
	opaque="$(python3 "$here/count_opaque_pixels.py" "$brand_png")" \
		|| fail "the step-up window's mark could not be read as a PNG: $brand_png"
	[ "$opaque" -gt 1000 ] \
		|| fail "the step-up window's mark has $opaque opaque pixel(s): it is transparent or blank. A transparent image does not LOOK broken, which is why this is measured rather than looked at: $brand_png"
	ok "the step-up window's mark draws $opaque opaque pixels"
fi

icon_named="$(defaults read "$app/Contents/Info.plist" CFBundleIconFile 2>/dev/null || true)"
if [ -n "$icon_named" ]; then
	[ -s "$app/Contents/Resources/${icon_named}.icns" ] \
		|| fail "Info.plist names the bundle icon \"$icon_named\" and Contents/Resources/${icon_named}.icns is missing or empty — Finder and the System Settings lists would show the generic icon while the bundle claims otherwise"
	ok "the bundle icon named in Info.plist is present ($(wc -c < "$app/Contents/Resources/${icon_named}.icns" | tr -d " ") bytes)"
else
	# Not fatal: a build made without the brand asset is a legitimate development build. What must never
	# happen quietly is naming an icon that is not there.
	echo "note: this bundle names no CFBundleIconFile — Finder will show the generic application icon"
fi

echo "verify_macos_ne_packaging: PASS — packaging is consistent; activation cannot silently mismatch."
