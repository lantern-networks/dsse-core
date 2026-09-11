#!/bin/sh
# Build the macOS agent .app — WITH its embedded .systemextension — from scratch, out of the OSS Swift package.
#
# Why this exists (2026-07-27): the repo had NO from-scratch build. The original assembler
# (prototype/scripts/generate_unsigned_runnable_system_extension_artifact.rb) and phase2_deploy.sh were both
# stale-guarded and exit 2 — they predate the OSS extraction that moved the package to
# prototype/oss/clients/macos-network-extension and renamed the products Dsse* -> Dsse*. The only
# maintained path, redeploy_macos_ne.sh, REQUIRES an already-installed app because it just swaps binaries into
# it. So /Applications/LanternDsseAgent.app was effectively irreproducible: lose it and the macOS agent could
# not be rebuilt. This closes that hole, and is the prerequisite for any installer (.pkg) work.
#
# It NEVER touches an installed app. It writes a fresh bundle into an output directory you name.
#
#   sh deploy/reference/build_macos_ne_app.sh [output-dir]      # default: var/macos-ne-app
#
# Everything identity-shaped is a variable, defaulting to what is installed today, so behaviour is unchanged
# and the Lantern Networks rebrand (new team + reverse-DNS bundle ids) is a variable swap, not a hunt:
#   DSSE_APP_BUNDLE_ID   app bundle id           (extension id is ALWAYS this + ".networkextension" — the agent
#                                                 derives its activation target that way at runtime, so this is
#                                                 an invariant, not a choice; see verify_macos_ne_packaging.sh)
#   DSSE_APP_EXEC        app executable name      (SwiftPM product DsseAgent is RENAMED to this)
#   DSSE_SYSEXT_EXEC     provider executable name (SwiftPM product DsseAppProxyProvider is RENAMED to this)
#   DSSE_APP_GROUP       app group id             (NEMachServiceName is ALWAYS this + ".networkextension")
#   DSSE_DISPLAY_NAME    CFBundleName and the name in the system-extension approval dialog the CUSTOMER reads
#   DSSE_SYSEXT_USAGE    that dialog's full sentence, if the default wording is not wanted
#   DSSE_TEAM_ID         Apple team id
#   DSSE_VERSION         CFBundleShortVersionString
#   DSSE_BUILD           CFBundleVersion (default: UTC timestamp, so every build is newer than the last)
#   DSSE_PROFILE         the APP's embedded.provisionprofile   (default: reuse the installed app's)
#   DSSE_SYSEXT_PROFILE  the EXTENSION's                       (default: reuse the installed extension's)
#   CODESIGN_IDENTITY    signing identity (default: whichever identity in this keychain the profile authorises)
#   DSSE_SKIP_SIGN=1     assemble only, do not sign (the verifier will then fail — signing is what it checks)
#
# ★ THE TWO PROFILES ARE DIFFERENT DOCUMENTS and this script used to embed one file in both places. It is not a
# cosmetic duplication: a profile is issued FOR a bundle id, so the app's profile inside the .systemextension
# authorises "…dsse.agent" for a bundle signed as "…dsse.agent.networkextension". Development signing tolerates
# that; Developer ID does not. The installed lab app carries the correct pair (it predates this script), so a
# rebuild would have QUIETLY DOWNGRADED a working bundle into one whose extension cannot activate.
#
# ★ Nothing below hardcodes an entitlement value or a signing identity. Both are read from the profile being
# embedded — see lib_provisioning_profile.sh for why that is the only way this can't silently drift.
set -eu
umask 022 # Installed app resources must be readable by the GUI user, even when the builder uses 077.

here="$(cd "$(dirname "$0")" && pwd)"
tree="$(cd "$here/../../.." && pwd)"   # clients/… is one below the tree root, in the monorepo and in a clone alike
. "$here/lib_provisioning_profile.sh"
pkg="$tree/clients/macos-network-extension"
out="${1:-$tree/var/macos-ne-app}"
# Resolve to an ABSOLUTE path: `defaults read`, which the verifier uses to read the Info.plists, silently fails
# on a relative path ("CFBundleIdentifier missing"), so a relative output dir would look like a packaging bug.
mkdir -p "$out"
out="$(cd "$out" && pwd)"

app_id="${DSSE_APP_BUNDLE_ID:-jp.co.lantern-networks.dsse.agent}"
app_exec="${DSSE_APP_EXEC:-LanternDsseAgent}"
sx_exec="${DSSE_SYSEXT_EXEC:-DsseAppProxyProvider}"
app_group="${DSSE_APP_GROUP:-group.jp.co.lantern-networks.dsse.app-group}"
team="${DSSE_TEAM_ID:-M4U8GSBL6C}"
version="${DSSE_VERSION:-$(sh "$tree/scripts/build_stamp.sh" --version)}"  # single source: the tree's VERSION
build="${DSSE_BUILD:-$(date -u +%Y%m%d%H%M%S)}"
min_os="${DSSE_MIN_OS:-13.0}"

# ★ The one string in this build a CUSTOMER reads. macOS shows it in the dialog that asks whether to allow the
# system extension — the single moment where a person decides whether this product may see their traffic — so it
# is neither decoration nor a log line. It was hardcoded to a sentence naming the retired product name and
# claiming a territory the brand does not claim, and it was written in one language.
#
# ★ THE DEFAULT IS ENGLISH BECAUSE THE READER OF THIS TREE IS ANYWHERE (2026-09-04, on the day this build moved
# into the published half). A default sentence in one language is a default for the person who wrote it: every
# receiver's customers would have met a dialog in a language nobody chose. Set DSSE_SYSEXT_USAGE to the
# sentence YOUR customers should read — it is the one moment a person decides whether this product may see
# their traffic, and it should be in their words.
display="${DSSE_DISPLAY_NAME:-Lantern DSSE Agent}"
sx_usage="${DSSE_SYSEXT_USAGE:-${display} uses a system extension to inspect and control network connections, following the policy set by your organization.}"

sx_id="${app_id}.networkextension"                  # invariant — do not parameterize
mach="${app_group}.networkextension"                # invariant — must match the provider's NEMachServiceName

[ -d "$pkg" ] || { echo "build_macos_ne_app: OSS package not found at $pkg"; exit 1; }

echo "==> building DsseAgent + DsseAppProxyProvider from $pkg"
SWIFTPM_CACHE_PATH="$pkg/.cache/swiftpm" swift build --disable-sandbox --quiet --product DsseAgent --package-path "$pkg"
SWIFTPM_CACHE_PATH="$pkg/.cache/swiftpm" swift build --disable-sandbox --quiet --product DsseAppProxyProvider --package-path "$pkg"
bin="$(SWIFTPM_CACHE_PATH="$pkg/.cache/swiftpm" swift build --disable-sandbox --show-bin-path --package-path "$pkg")"
[ -x "$bin/DsseAgent" ] && [ -x "$bin/DsseAppProxyProvider" ] || { echo "build_macos_ne_app: built binaries missing in $bin"; exit 1; }

app="$out/${app_exec}.app"
sx="$app/Contents/Library/SystemExtensions/${sx_id}.systemextension"
echo "==> assembling $app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$sx/Contents/MacOS" "$app/Contents/Resources"

# ★★★ THE MARK, IN THE TWO PLACES macOS ACTUALLY HAS ONE (2026-09-07, after Windows did the same five).
#
# Windows put it in five surfaces; three of them do not exist here and it is worth writing down WHY rather
# than leaving the next person to rediscover it. The app sets NSApplication .accessory (main.swift), so it
# has no Dock tile and no Cmd-Tab entry EVEN WHILE ITS WINDOW IS UP, and macOS puts no application icon in a
# window's title bar. What is left is the bundle icon — Finder, /Applications, and the System Settings lists
# where a person decides whether to trust this extension — and the step-up window's own header, which is the
# one that carries the same weight as the Windows header: the only screen where somebody types a password.
#
# ★ THE SYMBOL IS COPIED, NOT REDRAWN, and it is byte-for-byte the file Windows ships, so the two windows
# carry the same mark rather than two drawings of it.
brand_png="$pkg/brand/lantern-symbol.png"
if [ -f "$brand_png" ]; then
	cp "$brand_png" "$app/Contents/Resources/lantern-symbol.png"
	# ★★★ AN ICON THAT WAS NEVER BUILT LOOKS EXACTLY LIKE ONE THAT WAS. iconutil is quiet about an iconset it
	# does not like, so the result is checked for existence and size here and for VISIBLE PIXELS by the
	# verifier — this deployment has already shipped a 512x512 brand PNG with not one opaque pixel in it, and
	# nobody saw it for weeks, because a transparent image does not look broken.
	iconset="$out/lantern.iconset"
	rm -rf "$iconset"; mkdir -p "$iconset"
	icon_ok=yes
	for sz in 16 32 128 256 512; do
		sips -z "$sz" "$sz" "$brand_png" --out "$iconset/icon_${sz}x${sz}.png" >/dev/null 2>&1 || icon_ok=no
		sips -z "$((sz * 2))" "$((sz * 2))" "$brand_png" --out "$iconset/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1 || icon_ok=no
	done
	if [ "$icon_ok" = yes ] && iconutil -c icns "$iconset" -o "$app/Contents/Resources/lantern.icns" >/dev/null 2>&1 &&
		[ -s "$app/Contents/Resources/lantern.icns" ]; then
		icon_plist_entry='	<key>CFBundleIconFile</key><string>lantern</string>'
		echo "==> bundle icon: $(wc -c < "$app/Contents/Resources/lantern.icns" | tr -d ' ') bytes"
	else
		# ★ NAMING AN ICON THAT IS NOT THERE IS WORSE THAN NAMING NONE: the bundle then shows the generic icon
		# with a plist that says otherwise, which reads as "the icon is broken" rather than "it was not built".
		icon_plist_entry=''
		echo "==> WARNING no bundle icon was produced (sips/iconutil) — shipping without CFBundleIconFile"
	fi
	rm -rf "$iconset"
else
	icon_plist_entry=''
	echo "==> WARNING $brand_png is absent — the step-up window will fall back to its wordmark alone"
fi

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>${app_exec}</string>
	<key>CFBundleIdentifier</key><string>${app_id}</string>
	<key>CFBundleName</key><string>${display}</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>${version}</string>
	<key>CFBundleVersion</key><string>${build}</string>
	<key>LSMinimumSystemVersion</key><string>${min_os}</string>
	<key>LSUIElement</key><true/>
${icon_plist_entry}
</dict>
</plist>
PLIST

# CFBundlePackageType MUST be SYSX. NEProviderClasses maps the App Proxy extension point to the Swift class by
# its MODULE-QUALIFIED name — the module is the SwiftPM target (DsseAppProxyProviderSkeleton), NOT the renamed
# executable, so this string does not follow DSSE_SYSEXT_EXEC.
cat > "$sx/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>${sx_exec}</string>
	<key>CFBundleIdentifier</key><string>${sx_id}</string>
	<key>CFBundleName</key><string>${sx_exec}</string>
	<key>CFBundlePackageType</key><string>SYSX</string>
	<key>CFBundleShortVersionString</key><string>${version}</string>
	<key>CFBundleVersion</key><string>${build}</string>
	<key>LSMinimumSystemVersion</key><string>${min_os}</string>
	<key>NetworkExtension</key>
	<dict>
		<key>NEMachServiceName</key><string>${mach}</string>
		<key>NEProviderClasses</key>
		<dict>
			<key>com.apple.networkextension.app-proxy</key><string>DsseAppProxyProviderSkeleton.DsseAppProxyProvider</string>
		</dict>
	</dict>
	<key>NSSystemExtensionUsageDescription</key><string>${sx_usage}</string>
</dict>
</plist>
PLIST

cp "$bin/DsseAgent" "$app/Contents/MacOS/$app_exec"
cp "$bin/DsseAppProxyProvider" "$sx/Contents/MacOS/$sx_exec"
chmod 755 "$app/Contents/MacOS/$app_exec" "$sx/Contents/MacOS/$sx_exec"

# The provisioning profile is what AUTHORIZES the NetworkExtension + system-extension entitlements. Without one
# the bundle still signs, but the system refuses to activate the extension.
#
# ★★★ IT IS NOT SCAVENGED FROM WHATEVER IS INSTALLED (2026-08-31, after uninstalling the agent made the
# product unbuildable). The default used to be the INSTALLED app's copy, which works right up until the
# machine does not have the product installed — a fresh checkout, a build host, or, as happened here, an
# operator who removed the agent because the deployment it belonged to was torn down. The material needed to
# BUILD the installer then lived only inside a thing the installer installs, and `dsse-uninstall` deleted it.
#
# So the order is: what the caller named, then this repository's declared signing directory, and only then
# the installed bundle. A build input has to have a home that does not depend on the machine's current state.
: "${DSSE_SIGNING_DIR:=$tree/var/signing}"
installed="/Applications/${app_exec}.app"
pick_profile() {
	# $1 = the declared filename in DSSE_SIGNING_DIR, $2 = the installed bundle's path
	if [ -f "$DSSE_SIGNING_DIR/$1" ]; then printf '%s\n' "$DSSE_SIGNING_DIR/$1"; else printf '%s\n' "$2"; fi
}
app_profile="${DSSE_PROFILE:-$(pick_profile app.provisionprofile "$installed/Contents/embedded.provisionprofile")}"
sx_profile="${DSSE_SYSEXT_PROFILE:-$(pick_profile systemextension.provisionprofile "$installed/Contents/Library/SystemExtensions/${sx_id}.systemextension/Contents/embedded.provisionprofile")}"

if [ "${DSSE_SKIP_SIGN:-0}" = "1" ]; then
	echo "==> DSSE_SKIP_SIGN=1 — assembled unsigned at $app"
	exit 0
fi

# FATAL rather than a warning, deliberately. The warning this replaces was printed into a build log nobody reads
# and produced a bundle indistinguishable from a good one until the extension failed to activate on a machine
# far from here. If you want an unsigned bundle, DSSE_SKIP_SIGN=1 says so out loud.
for p in "$app_profile" "$sx_profile"; do
	[ -f "$p" ] || { echo "build_macos_ne_app: no provisioning profile at $p"
		echo "   Put the pair in $DSSE_SIGNING_DIR as app.provisionprofile and systemextension.provisionprofile"
		echo "   (that is where this build looks first, so it does not depend on the agent being installed),"
		echo "   or set DSSE_PROFILE / DSSE_SYSEXT_PROFILE, or DSSE_SKIP_SIGN=1 to assemble without signing."; exit 1; }
done

pf="$out/.profiles"
mkdir -p "$pf"
dsse_profile_decode "$app_profile" "$pf/app.plist" || { echo "build_macos_ne_app: $app_profile is not a provisioning profile"; exit 1; }
dsse_profile_decode "$sx_profile" "$pf/sysext.plist" || { echo "build_macos_ne_app: $sx_profile is not a provisioning profile"; exit 1; }

# ★ Each profile must be FOR the bundle it is embedded in. This is the check that catches the one-file-for-both
# mistake, and it catches a half-finished rebrand too: a Lantern bundle id with a page.shinnagi profile stops
# here rather than at a customer's Gatekeeper.
check_profile_for() {
	# $1 = decoded plist, $2 = bundle id, $3 = label
	want="${team}.$2"
	got="$(dsse_profile_app_identifier "$1" || true)"
	[ "$got" = "$want" ] || { echo "build_macos_ne_app: the $3 profile is for '$got' but the $3 is '$want' — wrong profile embedded"; exit 1; }
}
check_profile_for "$pf/app.plist" "$app_id" "app"
check_profile_for "$pf/sysext.plist" "$sx_id" "extension"

# Mixing kinds would ship an app that runs anywhere around an extension that runs on registered Macs only —
# an app that launches and never steers, which is the failure this tree keeps closing off.
app_kind="$(dsse_profile_kind "$pf/app.plist")"
sx_kind="$(dsse_profile_kind "$pf/sysext.plist")"
[ "$app_kind" = "$sx_kind" ] || { echo "build_macos_ne_app: profile kinds differ (app=$app_kind extension=$sx_kind) — both must be the same"; exit 1; }

# ★ The entitlement VALUE comes from the profile. Development grants "app-proxy-provider"; Developer ID grants
# "app-proxy-provider-systemextension"; the two are exclusive, so a constant here would be wrong for one of them
# in a way that signs cleanly and does not activate.
app_ne="$(dsse_profile_ne_appproxy "$pf/app.plist")" || { echo "build_macos_ne_app: the app profile grants no App Proxy entitlement"; exit 1; }
sx_ne="$(dsse_profile_ne_appproxy "$pf/sysext.plist")" || { echo "build_macos_ne_app: the extension profile grants no App Proxy entitlement"; exit 1; }

# The app group is named in the profile; a mismatch means DSSE_APP_GROUP and the portal disagree, and the
# symptom would be the agent and its extension failing to reach each other over their Mach service.
prof_group="$(dsse_profile_app_group "$pf/app.plist" || true)"
if [ -n "$prof_group" ] && [ "$prof_group" != "$app_group" ]; then
	echo "build_macos_ne_app: DSSE_APP_GROUP is '$app_group' but the profile names '$prof_group'"
	exit 1
fi

cp "$app_profile" "$app/Contents/embedded.provisionprofile"
cp "$sx_profile" "$sx/Contents/embedded.provisionprofile"
# Copying can preserve restrictive source modes (including downloaded profiles).
# The bundle contains public resources and executables, never enrollment secrets.
chmod -R u+rwX,go+rX,go-w "$app"
echo "==> embedded $app_kind profiles: $(dsse_profile_name "$pf/app.plist") / $(dsse_profile_name "$pf/sysext.plist")"
echo "==> App Proxy entitlement from the profile: $app_ne"

ents="$out/.entitlements"
mkdir -p "$ents"
cat > "$ents/app.entitlements" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key><string>${team}.${app_id}</string>
	<key>com.apple.developer.networking.networkextension</key><array><string>${app_ne}</string></array>
	<key>com.apple.developer.system-extension.install</key><true/>
	<key>com.apple.developer.team-identifier</key><string>${team}</string>
	<key>com.apple.security.application-groups</key><array><string>${app_group}</string></array>
</dict>
</plist>
PLIST
cat > "$ents/sysext.entitlements" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.application-identifier</key><string>${team}.${sx_id}</string>
	<key>com.apple.developer.networking.networkextension</key><array><string>${sx_ne}</string></array>
	<key>com.apple.developer.team-identifier</key><string>${team}</string>
	<key>com.apple.security.application-groups</key><array><string>${app_group}</string></array>
</dict>
</plist>
PLIST

# ★ CHOSEN BY FINGERPRINT, NOT BY NAME. The profile lists the certificates it authorises; the one to sign with
# is whichever of those this keychain holds. Selecting by name was a live hazard rather than a theoretical one:
# this keychain holds TWO "Developer ID Application" identities differing only in the operator's own name, and
# the old `sed` would have taken whichever sorted first. It also kept a person's name in a repo script, which
# this tree does not want.
identity="${CODESIGN_IDENTITY:-$(dsse_profile_identity "$pf/app.plist" || true)}"
[ -n "$identity" ] || {
	echo "build_macos_ne_app: this keychain holds none of the certificates the profile authorises."
	echo "  profile: $(dsse_profile_name "$pf/app.plist") ($app_kind)"
	echo "  fix: import the matching private key, or set CODESIGN_IDENTITY to override."
	exit 1
}

# Sign INNER FIRST, then the outer app — signing the app seals its contents, so a later inner signature would
# invalidate the outer seal. Always pass an EXPLICIT -i and --entitlements: --preserve-metadata takes them from
# the signature already on the binary, and a fresh `swift build` binary is ad-hoc signed with identifier
# "DsseAgent-<hash>" and NO entitlements, which silently produces a bundle that cannot activate (this exact
# trap cost a full debug session on 2026-06-27 — see redeploy_macos_ne.sh).
echo "==> signing with \"$(dsse_profile_identity_name "$identity")\" [$identity]"
codesign --force --timestamp --options runtime \
	-i "$sx_id" --entitlements "$ents/sysext.entitlements" -s "$identity" "$sx"
codesign --force --timestamp --options runtime \
	-i "$app_id" --entitlements "$ents/app.entitlements" -s "$identity" "$app"

# ★ DID THE CODE IDENTITY CHANGE? Ask before shipping, because the answer decides whether this build can talk
# to the devices already in the field (2026-08-10).
#
# A device key is created with an ACL naming the code that made it, so the DESIGNATED REQUIREMENT is what a
# device is actually bound to. Change the bundle id, the team, or the signing certificate — any one of them —
# and every provisioned device stops being able to use its own private key. The symptom is not a signing error:
# the install succeeds, the extension activates, the tunnel reports connected, and mTLS silently offers no
# client certificate.
#
# This session paid for that. The move from Apple Development to Developer ID was planned as a change of
# DISTRIBUTION FORMAT; it is also a discarding of every device identity, and nothing said so:
#
#   old: identifier "jp.co.lantern-networks.dsse.agent" … certificate leaf[subject.CN] = "Apple Development: …"
#   new: identifier "jp.co.lantern-networks.dsse.agent" … certificate 1[field.…6.2.6]   (Developer ID)
#
# FAILS rather than warns. A warning in a build log is read after the fleet is dark. Acknowledging it is one
# environment variable, which makes shipping the change a decision instead of a side effect.
ident_file="$here/macos_code_identity.json"
dr="$(codesign -d -r- "$app" 2>&1 | sed -n 's/^designated => //p')"
[ -n "$dr" ] || { echo "build_macos_ne_app: could not read the designated requirement of $app"; exit 1; }
dr_hash="$(printf '%s' "$dr" | shasum -a 256 | cut -d' ' -f1)"
prev_hash="$(sed -n 's/.*"designated_requirement_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' "$ident_file" 2>/dev/null | head -1)"
if [ -n "$prev_hash" ] && [ "$prev_hash" != "$dr_hash" ]; then
	prev_dr="$(sed -n 's/.*"designated_requirement"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$ident_file" 2>/dev/null | head -1)"
	if [ "${DSSE_CODE_IDENTITY_CHANGE_ACKNOWLEDGED:-0}" != "1" ]; then
		echo ""
		echo "REFUSING TO BUILD: the code identity CHANGED, which invalidates every provisioned device key."
		echo "  was: $prev_dr"
		echo "  now: $dr"
		echo ""
		echo "  A device key's ACL names the code that created it, so every device already in the field will be"
		echo "  unable to use its own private key with this build. It fails silently: install succeeds, the"
		echo "  extension activates, the tunnel says connected, and no client certificate is presented."
		echo "  See docs/bundle_id_change_breaks_device_identity.md."
		echo ""
		echo "  Ship it only with a re-provisioning plan, then:"
		echo "    DSSE_CODE_IDENTITY_CHANGE_ACKNOWLEDGED=1 sh $0 $*"
		echo ""
		exit 1
	fi
	echo "==> code identity CHANGED and was acknowledged — every provisioned device needs re-provisioning"
fi
# ★ THE PROVIDER EXECUTABLE NAME IS PART OF THE RECORD TOO (added 2026-08-11, after it reverted unnoticed).
#
# Building 0.2.0 with DSSE_APP_EXEC set but not DSSE_SYSEXT_EXEC produced an extension whose executable was
# named DsseAppProxyProvider — the retired codename — while 0.1.0 shipped DsseAppProxyProvider.
# It installed, activated, and steered perfectly, so nothing failed. What broke was everything that looks for
# the process BY NAME: the on-device verifier reported "the provider process is NOT running" on a machine whose
# provider was running and inspecting traffic. And a retired codename came back in a shipped artifact.
#
# Nothing caught it. The designated-requirement guard above compares the bundle id, the team and the signing
# certificate — the executable name is in none of those — and verify_macos_ne_packaging passed. The builder's
# default was the old name while the VERIFIER's default was the new one, and the two were never compared.
#
# So it joins the identity record, and a change is refused the same way: loudly, with the acknowledgement flag.
prev_exec="$(sed -n 's/.*"provider_executable": "\([^"]*\)".*/\1/p' "$ident_file" 2>/dev/null | head -1)"
if [ -n "$prev_exec" ] && [ "$prev_exec" != "$sx_exec" ] && [ "${DSSE_CODE_IDENTITY_CHANGE_ACKNOWLEDGED:-}" != "1" ]; then
	echo ""
	echo "REFUSING TO BUILD: the provider executable name changed."
	echo "  was: $prev_exec"
	echo "  now: $sx_exec"
	echo ""
	echo "  It installs and steers either way, so nothing will fail — but everything that finds the provider by"
	echo "  name stops working, starting with the on-device verifier, which will report the provider as NOT"
	echo "  running on a healthy machine. Set DSSE_SYSEXT_EXEC, or acknowledge deliberately:"
	echo "    DSSE_CODE_IDENTITY_CHANGE_ACKNOWLEDGED=1 sh $0 $*"
	echo ""
	exit 1
fi
# ★ ESCAPED. The designated requirement contains quotes — `identifier "jp.co…"` — and printf wrote them raw,
# so this file has never been valid JSON despite its name. Nothing noticed because everything that reads it
# uses sed; the first tool to try json.load() on it failed, which is how it was found. A file whose extension
# promises a format it does not hold is a trap for whoever writes the next reader.
dr_json="$(printf '%s' "$dr" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
printf '{\n  "designated_requirement": "%s",\n  "designated_requirement_sha256": "%s",\n  "bundle_id": "%s",\n  "team_id": "%s",\n  "provider_executable": "%s"\n}\n' \
	"$dr_json" "$dr_hash" "$app_id" "$team" "$sx_exec" > "$ident_file"
# And check it: a writer that believes it escaped correctly and a file that parses are different claims.
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$ident_file" 2>/dev/null || {
	echo "build_macos_ne_app: the identity record at $ident_file is not valid JSON after writing it" >&2
	exit 1
}

echo "==> verifying"
sh "$here/verify_macos_ne_packaging.sh" "$app"
echo "==> built: $app"
