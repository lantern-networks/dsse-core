#!/bin/sh
# Facts read out of a provisioning profile, so that nothing downstream has to GUESS them.
#
# Why this file exists (2026-08-10). Switching the macOS agent from Development signing to Developer ID
# distribution surfaced a mismatch that neither codesign nor Gatekeeper would have reported:
#
#   Development profile grants:   app-proxy-provider
#   Developer ID profile grants:  app-proxy-provider-systemextension
#
# The two are EXCLUSIVE — neither profile lists the other's value (measured on all four profiles issued to team
# M4U8GSBL6C). Signed entitlements must be a subset of what the embedded profile authorises, so a build script
# that hardcodes either string produces, for the other profile, a bundle that signs cleanly, passes
# `codesign --verify`, installs, launches — and whose system extension the system then refuses to activate.
# That is exactly the "silent un-steer" class verify_macos_ne_packaging.sh exists to prevent, arriving by a new
# route: the packaging is internally consistent, and wrong anyway, because it disagrees with a document that
# lives outside the bundle.
#
# ★ THE PROFILE IS THE AUTHORITY. Rather than teach the build about two flavours and pick with a flag — a flag
# is one more thing that can be set wrong, and its being wrong is invisible until a customer's Mac won't steer —
# every value below is READ FROM THE PROFILE ABOUT TO BE EMBEDDED. A build cannot then contradict the document
# it ships.
#
# ★ AND THE SIGNING IDENTITY IS CHOSEN BY FINGERPRINT, NOT BY NAME. A profile carries the certificates it
# authorises; the identity to sign with is whichever of those this keychain holds. This removes the last place a
# developer's own name appears in a build (there are currently two "Developer ID Application" identities in this
# keychain — one personal, one the company — and choosing by name would silently pick either), and it means a
# profile/identity mismatch fails at BUILD time rather than as a Gatekeeper refusal on someone else's Mac.
#
# Usage:  . "$here/lib_provisioning_profile.sh"
# All functions take the path of a DECODED profile plist (see dsse_profile_decode) and print one value.

# dsse_profile_decode <profile.provisionprofile> <out.plist>
# A .provisionprofile is CMS-signed; `security cms -D` unwraps it. Failure here means the file is not a profile
# at all, which is worth distinguishing from a profile that lacks a key.
dsse_profile_decode() {
	security cms -D -i "$1" > "$2" 2>/dev/null || return 1
	[ -s "$2" ] || return 1
}

# dsse_profile_name <plist> — the portal-side name, for logs only.
dsse_profile_name() {
	plutil -extract Name raw -o - "$1" 2>/dev/null
}

# dsse_profile_app_identifier <plist> — "<TEAM>.<bundle id>" this profile is for.
#
# The single most useful assertion available: embedding the app's profile inside the .systemextension is an easy
# mistake (they are different files with the same basename) and produces a bundle whose extension will not
# activate. The installed lab app happens to carry the right pair, but the build script collapsed them to one
# until this was added.
dsse_profile_app_identifier() {
	plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - "$1" 2>/dev/null
}

# dsse_profile_ne_appproxy <plist> — the App Proxy value THIS profile grants.
#
# Order matters only for readability: the JSON is matched with the closing quote included, so
# "app-proxy-provider-systemextension" cannot satisfy the "app-proxy-provider" pattern.
dsse_profile_ne_appproxy() {
	vals="$(plutil -extract 'Entitlements.com\.apple\.developer\.networking\.networkextension' json -o - "$1" 2>/dev/null)" || return 1
	case "$vals" in
	*'"app-proxy-provider-systemextension"'*) echo "app-proxy-provider-systemextension" ;;
	*'"app-proxy-provider"'*) echo "app-proxy-provider" ;;
	*) return 1 ;;
	esac
}

# dsse_profile_app_group <plist> — the explicitly-named app group, ignoring the "<TEAM>.*" wildcard.
#
# Both forms are granted (measured), and the wildcard would satisfy any string — including a typo. Returning the
# named one lets a build assert it is shipping the group the portal actually knows about.
dsse_profile_app_group() {
	vals="$(plutil -extract 'Entitlements.com\.apple\.security\.application-groups' json -o - "$1" 2>/dev/null)" || return 1
	printf '%s' "$vals" | tr ',' '\n' | sed -n 's/.*"\(group\.[^"]*\)".*/\1/p' | head -1
}

# dsse_profile_kind <plist> — "developer-id" or "development".
#
# ProvisionsAllDevices is the property that MATTERS rather than a label: it is the difference between a build
# that runs on any Mac and one that runs only on Macs listed in the profile. A Development profile instead
# carries ProvisionedDevices.
dsse_profile_kind() {
	if plutil -extract ProvisionsAllDevices raw -o - "$1" >/dev/null 2>&1; then
		echo "developer-id"
	else
		echo "development"
	fi
}

# dsse_profile_identity <plist> — SHA-1 of the first codesigning identity in THIS keychain that the profile
# authorises. Printed as a hash because codesign accepts one for -s, and a hash cannot be ambiguous the way two
# identities sharing a common name prefix can.
dsse_profile_identity() {
	n="$(plutil -extract DeveloperCertificates raw -o - "$1" 2>/dev/null)" || return 1
	have="$(security find-identity -v -p codesigning 2>/dev/null)"
	i=0
	while [ "$i" -lt "$n" ]; do
		sha="$(plutil -extract "DeveloperCertificates.$i" raw -o - "$1" 2>/dev/null | base64 -d 2>/dev/null | shasum -a 1 | cut -d' ' -f1 | tr 'a-z' 'A-Z')"
		case "$have" in
		*"$sha"*)
			echo "$sha"
			return 0
			;;
		esac
		i=$((i + 1))
	done
	return 1
}

# dsse_profile_identity_name <sha1> — the human name of an identity, for the build log. Never used to SELECT.
dsse_profile_identity_name() {
	security find-identity -v -p codesigning 2>/dev/null | sed -n "s/.*$1 \"\(.*\)\"/\1/p" | head -1
}
