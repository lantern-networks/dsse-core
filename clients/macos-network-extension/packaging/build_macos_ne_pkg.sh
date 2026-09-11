#!/bin/sh
# Build a distributable macOS installer (.pkg) for the NE agent — the counterpart of the Windows WiX MSI.
#
# Windows ships packaging/DsseAgent.wxs (MajorUpgrade, a CompatGate custom action, service install, config-store
# hardening, RecoverNetwork on uninstall) plus a Burn bootstrapper. macOS had NOTHING: the only way to get the
# agent onto a Mac was a hand-run "swift build -> cp -> re-sign" dance. This is the macOS half of that parity.
#
#   sh deploy/reference/build_macos_ne_pkg.sh [output-dir]     # default: var/macos-ne-pkg
#
# Reuses the SAME identity variables as build_macos_ne_app.sh, so the Lantern Networks rebrand stays a variable
# swap across both: DSSE_APP_BUNDLE_ID / DSSE_APP_EXEC / DSSE_SYSEXT_EXEC / DSSE_APP_GROUP / DSSE_TEAM_ID /
# DSSE_VERSION / DSSE_BUILD / DSSE_MIN_OS.
#
#   DSSE_APP_SRC        use this already-built .app instead of building one
#   DSSE_INSTALLER_SIGN "Developer ID Installer: ..." — override; normally detected, see below
#   DSSE_NOTARY_PROFILE notarytool keychain profile name (default: dsse-notary)
#   DSSE_ALLOW_UNNOTARIZED=1  produce a Developer ID pkg WITHOUT notarizing it, and say so loudly
#
# ★ THE APP DECIDES WHAT THIS PACKAGE HAS TO BE (2026-08-10). Whether to sign the product archive, and whether
# to notarize it, are read from the KIND of provisioning profile embedded in the .app being packaged — not from
# a flag. A Developer ID app inside an unsigned pkg is a distribution build that stops at the last metre; a
# Development app inside a signed, notarized pkg is a lab build dressed as a release. Both are things a flag
# lets you do by forgetting, and neither fails until the artifact is on a machine that is not this one.
#
# ★ AND THE BUILD ASKS GATEKEEPER, rather than concluding from exit codes. `notarytool` succeeding and the
# ticket being STAPLED are different facts: a package that notarized but was never stapled works here — where
# the ticket can be fetched online — and is refused on the offline machine of the customer who most needs it to
# work. Same shape as the certificate rollout that applied cleanly and never reached the devices
# (project_cert_replacement_must_verify_as_a_device): the last check has to be the one the endpoint performs.
set -eu
umask 022 # Payload directories must remain traversable after PackageKit assigns root ownership.

here="$(cd "$(dirname "$0")" && pwd)"
tree="$(cd "$here/../../.." && pwd)"   # clients/… is one below the tree root, in the monorepo and in a clone alike
. "$here/lib_provisioning_profile.sh"
out="${1:-$tree/var/macos-ne-pkg}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

app_id="${DSSE_APP_BUNDLE_ID:-jp.co.lantern-networks.dsse.agent}"
app_exec="${DSSE_APP_EXEC:-LanternDsseAgent}"
version="${DSSE_VERSION:-$(sh "$tree/scripts/build_stamp.sh" --version)}"  # single source: the tree's VERSION
build="${DSSE_BUILD:-$(date -u +%Y%m%d%H%M%S)}"
min_os="${DSSE_MIN_OS:-13.0}"
# ★ The agent-config schema the preinstall gate demands. It MUST equal the value the control plane's publisher
# writes (cmd/edge/network_extension_snapshot_publisher.go). If the two ever drift, every install refuses a
# configuration that is in fact correct — so the pairing is pinned by TestMacOSInstallerConfigSchemaMatchesPublisher
# rather than by two people remembering.
config_schema="dsse_agent_config.v1"
pkg_id="${DSSE_PKG_ID:-${app_id}.pkg}"

# ---- 1. the .app ------------------------------------------------------------------------------------------
if [ -n "${DSSE_APP_SRC:-}" ]; then
	src_app="$DSSE_APP_SRC"
	[ -d "$src_app" ] || { echo "build_macos_ne_pkg: DSSE_APP_SRC not found: $src_app"; exit 1; }
	echo "==> using prebuilt app: $src_app"
else
	echo "==> building the app first"
	# ★ THE FAILURE HAS TO REACH THE PERSON WHO RAN THIS (2026-08-14). `>/dev/null` discarded the app build's
	# stdout, and that is where its refusals are written. A build stopped by the code-identity guard — which
	# prints the OLD and NEW designated requirements and the exact flag to acknowledge them — produced three
	# lines here and no reason at all, and the reason was only readable by running the inner script by hand.
	# A caller that silences its callee turns a careful explanation into an unexplained exit code.
	if ! DSSE_BUILD="$build" sh "$here/build_macos_ne_app.sh" "$out/app" > "$out/.app-build.log" 2>&1; then
		echo "FAIL: the app build refused. Its own words:" >&2
		cat "$out/.app-build.log" >&2
		exit 1
	fi
	src_app="$out/app/${app_exec}.app"
fi
[ -d "$src_app" ] || { echo "build_macos_ne_pkg: app bundle missing at $src_app"; exit 1; }
sh "$here/verify_macos_ne_packaging.sh" "$src_app"

# ---- 1b. what kind of package does this app require? ------------------------------------------------------
app_prof="$src_app/Contents/embedded.provisionprofile"
app_kind="development"
if [ -f "$app_prof" ] && dsse_profile_decode "$app_prof" "$out/.app-profile.plist"; then
	app_kind="$(dsse_profile_kind "$out/.app-profile.plist")"
fi
echo "==> the app is a $app_kind build"

installer_sign="${DSSE_INSTALLER_SIGN:-}"
if [ "$app_kind" = "developer-id" ] && [ -z "$installer_sign" ]; then
	# Signing the product archive needs a Developer ID INSTALLER certificate — a different certificate from the
	# Developer ID Application one that signed the app, and one that no provisioning profile names, so unlike
	# the app signature there is nothing authoritative to resolve it against. Matched by name, therefore, but
	# AMBIGUITY IS FATAL rather than resolved by taking the first: the sibling keychain already holds two
	# Developer ID Application identities differing only by whose name is on them, and the day a second
	# Installer certificate exists is the day "head -1" quietly signs a release with the wrong one.
	found="$(security find-identity -v 2>/dev/null | grep 'Developer ID Installer:' || true)"
	count="$(printf '%s' "$found" | grep -c . || true)"
	case "$count" in
	0) echo "build_macos_ne_pkg: the app is a Developer ID build but this keychain holds no 'Developer ID Installer' certificate"; exit 1 ;;
	1) installer_sign="$(printf '%s\n' "$found" | sed -n 's/^[[:space:]]*[0-9]*)[[:space:]]*\([0-9A-F]\{40\}\)[[:space:]].*/\1/p')" ;;
	*)
		echo "build_macos_ne_pkg: more than one Developer ID Installer certificate — set DSSE_INSTALLER_SIGN to choose:"
		printf '%s\n' "$found"
		exit 1
		;;
	esac
fi

# ---- 2. payload -------------------------------------------------------------------------------------------
# Laid out as an absolute filesystem image (install-location /), so the LaunchAgent ships as PAYLOAD rather
# than being written by a script. Payload files are tracked by the receipt, so an uninstall/upgrade can reason
# about them; files a postinstall script writes are invisible to the installer database.
root="$out/root"
scripts="$out/scripts"
rm -rf "$root" "$scripts"
mkdir -p "$root/Applications" "$root/Library/LaunchAgents" "$root/Library/LaunchDaemons" \
         "$root/Library/Application Support/Dsse/bin" "$scripts"
cp -R "$src_app" "$root/Applications/"

# ---- the updater daemon ------------------------------------------------------------------------------------
#
# ★ WHY A ROOT DAEMON AND NOT THE AGENT. `installer -pkg -target /` needs root and an unattended update cannot
# prompt, so the component that performs an update cannot live in the user's app. It also must not live in the
# system extension: the extension is what an update REPLACES, and a component that installs its own replacement
# is waiting to be killed halfway through the privileged half.
#
# A DAEMON, not an agent: it must run with no one logged in. That is the ordinary case for the machines this
# matters most on — a laptop closed on a desk at 02:00 is exactly the device a maintenance window is for.
# ★★ IT IS STAMPED, AND SHIPPING IT UNSTAMPED COST AN INVESTIGATION (2026-08-13). Every packaged updater so far
# reported `dsse-updater 0.0.0-dev+unknown`, because this build never used scripts/build_stamp.sh — the file
# whose own header says it exists so "a binary can always answer what am I". So the fleet ran an updater that
# could not name its own build.
#
# The cost was concrete and immediate. Asked whether a device was performing the new publisher check, the only
# way to tell was that a log line was ABSENT from --status — inferring a build's age from a missing sentence, on
# the one component whose entire job is to decide which code runs as root. With a stamp it is one field.
#
# Not fatal if the stamp cannot be produced: a build on a machine with no git still has a VERSION file, and
# refusing to package over provenance metadata would be the wrong trade for a component this deployment needs.
# ★ THE VERSION IS THE PACKAGE'S, NOT THE REPOSITORY'S. build_stamp.sh reads the the tree's VERSION file (0.1.0
# today), while this package — and everything the fleet counts, poisons, ratchets and rolls back — is
# $version, from DSSE_VERSION. Stamping the repo number would give the updater a SECOND version vocabulary that
# disagrees with the one every other surface uses, which is worse than the unstamped state it replaces: an
# operator comparing "device reports 0.1.0" against a fleet tracking 0.2.9 would conclude the wrong thing twice.
# The commit and date still come from the one stamp helper.
updater_bin="$out/dsse-updater"
updater_stamp="$(sh "$tree/scripts/build_stamp.sh" 2>/dev/null || true)"
if [ -n "$updater_stamp" ]; then
	updater_stamp="$(printf '%s' "$updater_stamp" | sed "s|-X main.buildVersion=[^ ]*|-X main.buildVersion=$version|")"
else
	echo "build_macos_ne_pkg: WARNING the build stamp could not be produced; the updater will report 0.0.0-dev+unknown and no device will be able to say which build it is running"
fi
( cd "$tree" && GOOS=darwin go build -ldflags "$updater_stamp" -o "$updater_bin" ./clients/macos/updater ) \
	|| { echo "FAIL: could not build the updater"; exit 1; }
# ★ READ BACK FROM THE ARTEFACT. An -X path that no longer matches the variable's package stamps NOTHING and
# says nothing — the exact silent failure this block exists to end, so it is not taken on trust.
updater_says="$("$updater_bin" --version 2>/dev/null || true)"
case "$updater_says" in
*"$version"*) : ;;
*) echo "build_macos_ne_pkg: WARNING the updater reports '$updater_says' rather than $version — the -X paths no longer match its variables, and every device will again be unable to say which build it runs" ;;
esac
cp "$updater_bin" "$root/Library/Application Support/Dsse/bin/dsse-updater"
chmod 755 "$root/Library/Application Support/Dsse/bin/dsse-updater"

# ★★★ THE PROFILE VERIFIER TRAVELS TOO, BECAUSE macOS CANNOT DO THIS CHECK ITSELF. The postinstall's only
# crypto tool is /usr/bin/openssl, which on macOS is LibreSSL, and it will not so much as load an Ed25519
# public key — measured on 3.3.6. Without a verifier on the device the postinstall's only options were to
# decode the profile unchecked (what it did, and what let a profile name its own verifier) or to derive
# nothing. So it ships, next to the updater and the uninstaller, for the same reason they do.
profileverify_bin="$out/dsse-profileverify"
( cd "$tree" && GOOS=darwin go build -o "$profileverify_bin" ./cmd/dsse-profileverify ) \
	|| { echo "FAIL: could not build the profile verifier"; exit 1; }
cp "$profileverify_bin" "$root/Library/Application Support/Dsse/bin/dsse-profileverify"
chmod 755 "$root/Library/Application Support/Dsse/bin/dsse-profileverify"

# ★ THE VERIFIER AND THE UNINSTALLER TRAVEL WITH THE PACKAGE.
#
# A check that lives only in this repository does not exist on a customer's Mac, and the one moment it is
# needed is on a machine nobody can `git clone` onto. Same for removal: the ORDER matters (configuration first,
# then deactivate, then delete) and only the containing app can do the first two — leaving that order in a
# runbook means the day it is done wrong the machine loses all connectivity, which this session watched happen.
cp "$here/verify_macos_install.sh" "$root/Library/Application Support/Dsse/bin/dsse-verify-install"
chmod 755 "$root/Library/Application Support/Dsse/bin/dsse-verify-install"

cat > "$root/Library/Application Support/Dsse/bin/dsse-uninstall" <<UNINST
#!/bin/sh
# Remove the DSSE agent in the ONLY order that is safe.
#
# ★ Configuration FIRST, then deactivate, then delete — and both of the first two can only be done by the
# containing app, so they must happen while it still exists. Deleting the app first strands an activated system
# extension and a transparent-proxy configuration whose provider can never load: the machine then carries a
# proxy that captures traffic and cannot carry it. That is total loss of connectivity, and it is permanent
# until someone knows to look here.
set -eu
APP="/Applications/${app_exec}.app"
[ "\$(id -u)" = "0" ] || { echo "dsse-uninstall: run with sudo"; exit 1; }

# ★★★ THE CONFIGURATION BELONGS TO THE CONSOLE USER, NOT TO ROOT (2026-08-29, measured). This script must be
# root to delete the app and boot out the daemon — and root is shown an EMPTY Network Extension preference
# list, so the app it ran replied "no managed configuration present; nothing to remove / error=none" and this
# script went on to delete the only thing that could ever remove it. That is the permanent connectivity loss
# the header above warns about, produced by the documented exit itself. Run that step as the console user.
uid="\$(stat -f %u /dev/console 2>/dev/null || echo 0)"
if [ "\$uid" = "0" ]; then
	echo "dsse-uninstall: nobody is logged in at the console. The transparent proxy configuration can only be"
	echo "   removed by the user who owns it, so removing the app now would strand it and take this machine's"
	echo "   network with it. Log in and run this again." >&2
	exit 1
fi
if [ -d "\$APP" ]; then
	echo "==> removing the transparent proxy configuration and deactivating the extension (as console user \$uid)"
	if ! launchctl asuser "\$uid" sudo -u "#\$uid" "\$APP/Contents/MacOS/${app_exec}" --uninstall; then
		echo "dsse-uninstall: the app could not remove the transparent proxy configuration. STOPPING with the" >&2
		echo "   app still installed — deleting it now would leave a proxy that captures every flow, a provider" >&2
		echo "   that can never load, and nothing on this machine able to undo either." >&2
		exit 1
	fi
	sleep 8
else
	echo "dsse-uninstall: \$APP is already gone — its proxy configuration and extension may be STRANDED."
	echo "   Check: systemextensionsctl list | grep ${app_id}"
fi
echo "==> stopping services"
launchctl bootout system "/Library/LaunchDaemons/${app_id}.updater.plist" 2>/dev/null || true
uid="\$(stat -f %u /dev/console 2>/dev/null || echo 0)"
[ "\$uid" != "0" ] && launchctl bootout "gui/\$uid/${app_id}" 2>/dev/null || true
echo "==> removing files"
[ "\$uid" != "0" ] && launchctl bootout "gui/\$uid/${app_id}.trust-environment" 2>/dev/null || true
rm -f "/Library/LaunchAgents/${app_id}.trust-environment.plist" "/Library/Application Support/Dsse/bin/set-gui-trust-environment"
rm -f "/Library/LaunchAgents/${app_id}.plist" "/Library/LaunchDaemons/${app_id}.updater.plist"
rm -rf "\$APP"

# ★★★ SAY WHETHER THE IDENTITY ACTUALLY SURVIVED, BECAUSE IT DOES NOT (2026-08-29, measured on a real Mac).
# This script printed "Device identity and configuration were KEPT" and touched no keychain — and the private
# key was gone anyway: it lives in the system extension's keychain access group, and deactivating the
# extension takes it. What is left behind is the CERTIFICATE and the pointer file naming it, which is the
# worst of the three possible states. The device then reads as enrolled to itself and stays registered on the
# Edge, so a later install is refused 403 "already enrolled — a renewal proves possession of the one being
# replaced": possession of a key that no longer exists. The machine is locked out under its own name, and
# nothing on it says so. A claim this script cannot keep must not be printed as though it were kept.
echo "==> what survived"
cn="\$(hostname -s)"
ids="\$(security find-identity -v /Library/Keychains/System.keychain 2>/dev/null \\
        | sed -n 's/.* \\([0-9][0-9]*\\) valid identities found/\\1/p')"
if [ "\${ids:-0}" -gt 0 ] && security find-identity -v /Library/Keychains/System.keychain 2>/dev/null | grep -q "\$cn"; then
	echo "   device identity: KEPT (\$cn is still usable). Configuration under /Library/Application Support/Dsse was kept."
else
	echo "   device identity: GONE. The private key left with the system extension, and this Mac can no longer"
	echo "   prove the name '\$cn'. Re-installing will be refused with 403 'already enrolled'."
	echo "   Clearing the claim it can no longer back, so the device is honestly un-enrolled:"
	for sha in \$(security find-certificate -a -c "\$cn" -Z /Library/Keychains/System.keychain 2>/dev/null \\
	              | sed -n 's/^SHA-256 hash: //p'); do
		security delete-certificate -Z "\$sha" /Library/Keychains/System.keychain >/dev/null 2>&1 \\
			&& echo "     removed the keyless certificate \$(echo "\$sha" | cut -c1-16)"
	done
	rm -f "/Library/Application Support/Dsse/device_identity_pointer.json"
	echo "   BEFORE INSTALLING AGAIN: remove this device in the Admin Console (Devices > \$cn > Remove device)"
	echo "   and approve it again for a fresh enrolment token. The Edge holds the registration, not this Mac."
	echo "   The rest of the configuration under /Library/Application Support/Dsse was kept."
fi

# ★★★ AND THE ROOT THIS PACKAGE TAUGHT THE MACHINE TO TRUST GOES WITH IT (2026-08-30). postinstall trusts the
# interception root the verified profile announces, because otherwise a steering device cannot load a page.
# A root left behind when the deployment goes is one whose key is now only somewhere on disk and which this
# machine still accepts for every name on the internet. Nine of them were found on one Mac that afternoon,
# from five deployments, four of which no longer existed — because nothing had ever removed one.
#
# Removed by FINGERPRINT, read from the certificate this package itself installed, so this deletes the root
# it added and nothing that merely resembles it. Never by subject: the same name belongs to more than one
# deployment during a rotation, and to two of them on a machine that moved organizations, so removing by name
# is not tidying up, it is an outage on the deployment that is still live.
#
# ★★★ AND THE MATERIAL THAT NAMES IT MUST OUTLIVE WHAT IS BEING REMOVED (2026-08-30, from the Windows side,
# where the mirror of this code had exactly this defect). Their custom action ran After the files were
# removed — and the artifact carrying the thumbprint was one of the files being removed, so the action had
# nothing left to name and the root survived every uninstall. The fix is a scheduling constant, which means
# the defect can come back through scheduling alone, with the removal code untouched and still correct.
#
# Here the root PEM lives under the configuration directory, which this script deliberately KEEPS, and it is
# deleted on the line after the certificate is gone. If anything ever moves interception-root.pem into the
# .app (removed above) or into anything else this script deletes first, this becomes the Windows defect.
root_pem="/Library/Application Support/Dsse/interception-root.pem"
if [ -f "\$root_pem" ]; then
	sha="\$(openssl x509 -in "\$root_pem" -noout -fingerprint -sha1 2>/dev/null \\
	        | sed 's/.*=//; s/://g')"
	if [ -n "\$sha" ] && security delete-certificate -Z "\$sha" /Library/Keychains/System.keychain >/dev/null 2>&1; then
		echo "   interception root: no longer trusted by this machine"
	else
		echo "   interception root: could not be removed from the System keychain — it is still trusted."
		echo "   Remove it by hand: Keychain Access > System > \$(openssl x509 -in "\$root_pem" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
	fi
	rm -f "\$root_pem"
fi

# ★★★ AND EVERYWHERE ELSE THE INSTALLER PUT IT (2026-08-31). The keychain is not the only place a tool looks,
# so postinstall also writes a bundle and points SSL_CERT_FILE and its siblings at it. A root removed from the
# keychain and left in a file bundle is still trusted, by exactly the tools whose failures are hardest to
# attribute — today both platforms found roots from deployments that no longer exist living in stores nobody
# had thought to look in. Removal follows the ledger the installer wrote, between the markers it used.
bundle="/Library/Application Support/Dsse/trusted_ca_bundle.pem"
if [ -f "\$bundle" ]; then
	# ★★★ TAKE THE ROOT OUT OF THE BUNDLE; DO NOT TAKE THE BUNDLE AWAY (2026-08-31, measured on this Mac
	# during a teardown, and named by the Windows session from the other side).
	#
	# Five of the six variables this installer sets have REPLACE semantics: SSL_CERT_FILE and its siblings do
	# not add to a tool's trust, they become it. Deleting the file they name does not return those tools to
	# the system store — it points them at nothing, and TLS stops working entirely for every process that was
	# already running when the uninstall happened, which no later shell setting can reach. Removing the
	# interception root from a bundle that still holds the public roots costs those processes one anchor they
	# no longer need; removing the file costs them all of them.
	#
	# ★ AND THE TOOL DOING THE TEARDOWN IS ONE OF THEM. terraform reads AWS_CA_BUNDLE. The destroy that
	# follows an uninstall would have failed for this reason, and an operator in that state cannot be helped
	# by a message telling them to open a new shell — they are already stopped. This is why it is fixed in the
	# structure rather than only announced.
	rebuilt="\$bundle.without-interception"
	if security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > "\$rebuilt" 2>/dev/null &&
		[ "\$(grep -c 'BEGIN CERTIFICATE' "\$rebuilt" 2>/dev/null || echo 0)" -gt 50 ]; then
		# Written THROUGH the existing file: anything holding it open keeps reading the same file.
		cat "\$rebuilt" > "\$bundle"
		rm -f "\$rebuilt"
		echo "   the tool trust bundle: the interception root was removed from it (\$(grep -c 'BEGIN CERTIFICATE' "\$bundle") public roots kept)"
		echo "   It is left in place on purpose: shells and daemons started before this uninstall still name it,"
		echo "   and deleting it would take TLS away from them entirely. It can be deleted after a restart."
	else
		# ★ IF THE PUBLIC ROOTS CANNOT BE READ, LEAVE THE BUNDLE ALONE AND SAY SO. A bundle rewritten to
		# nothing is the outage this is here to prevent, arriving by the hand meant to avoid it.
		rm -f "\$rebuilt"
		echo "   the tool trust bundle: LEFT AS IT IS — the system roots could not be read, so it was not"
		echo "   rewritten. It still contains this deployment's interception root: \$bundle"
	fi
fi
if [ -f /etc/zshenv ] && grep -q '>>> Lantern DSSE trust bundle >>>' /etc/zshenv 2>/dev/null; then
	awk '/# >>> Lantern DSSE trust bundle >>>/ { skip = 1 } !skip { print } /# <<< Lantern DSSE trust bundle <<</ { skip = 0 }' \
		/etc/zshenv > /etc/zshenv.dsse.new && mv /etc/zshenv.dsse.new /etc/zshenv && chmod 644 /etc/zshenv
	echo "   /etc/zshenv: the block this installer added was removed (nothing else in the file was touched)"
fi
for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS AWS_CA_BUNDLE; do
	launchctl unsetenv "\$v" 2>/dev/null || true
	[ "\$uid" != "0" ] && launchctl asuser "\$uid" launchctl unsetenv "\$v" 2>/dev/null || true
done
rm -f "/Library/Application Support/Dsse/trusted_roots_ledger.json"

# ★★★ AND IT SAYS WHAT IT IS LEAVING (2026-09-07, found on both platforms on the same day).
#
# Removing the agent stops what is running. It does not collect what identifies the deployment this machine
# belonged to: the profile, the key profiles are verified against, the anchors it adopted. Those name a
# deployment that may no longer exist, and the next thing to read them adopts it. Measured on a Windows box
# whose uninstall could not run: the agent came back bound to a deployment destroyed the day before. Measured
# here: a Mac still held a torn-down deployment's material after a successful uninstall.
#
# Deleting them is a decision — whether removing the agent should destroy a device's identity is not obvious,
# and a reinstall that has to spend a fresh approval is a real cost. Leaving them SILENTLY is not a decision,
# it is an omission. So this reports, in the project's own rule: fail loud, not fail closed.
left=""
for f in install_profile.json applied_install_profile.json profile_signing_key.txt \
         trust_anchors_adopted.pem trust_anchor_pointer.json agent_config.json; do
	[ -e "/Library/Application Support/Dsse/\$f" ] && left="\$left \$f"
done
if [ -n "\$left" ]; then
	echo "dsse-uninstall: ★ left in place, and they name the deployment this machine belonged to:\$left"
	echo "dsse-uninstall:   in /Library/Application Support/Dsse/ — anything that reads them later adopts that"
	echo "dsse-uninstall:   deployment, including one that no longer exists. Remove the directory if this"
	echo "dsse-uninstall:   machine is not going back to the same organization:"
	echo "dsse-uninstall:     sudo rm -rf \"/Library/Application Support/Dsse\""
fi
echo "dsse-uninstall: done."
UNINST
chmod 755 "$root/Library/Application Support/Dsse/bin/dsse-uninstall"

# ★ SIGN IT. Missed until Apple's notary service refused the package on 2026-08-10 with three errors against
# this one file: not signed with a Developer ID certificate, no secure timestamp, no hardened runtime.
#
# Worth naming rather than fixing quietly. Attention had been entirely on the .app — the bundle with the
# profile, the entitlements and the extension — while the payload carried, unsigned, the MOST privileged
# component in the product: a root LaunchDaemon whose job is to run `installer -pkg -target /`. The signing
# work was all pointed at the part that was already the subject of a verifier, and the part with no verifier
# had no signature at all. Notarization found it because notarization looks at every mach-O in the archive,
# which is precisely the property this build did not have.
#
# The identity comes from the app's profile for the same reason it does over there: it must be the certificate
# that profile authorises, and choosing by name is how the wrong one gets picked.
updater_identity="${CODESIGN_IDENTITY:-}"
if [ -z "$updater_identity" ] && [ -f "$out/.app-profile.plist" ]; then
	updater_identity="$(dsse_profile_identity "$out/.app-profile.plist" || true)"
fi
if [ -n "$updater_identity" ]; then
	codesign --force --timestamp --options runtime -i "${app_id}.updater" \
		-s "$updater_identity" "$root/Library/Application Support/Dsse/bin/dsse-updater"
	echo "==> signed the updater daemon"
	# ★ AND THE PROFILE VERIFIER, WHICH IS THE OTHER mach-O IN THIS PACKAGE. The comment above this block is
	# about an unsigned binary that shipped and was caught by notarization rather than by us; adding a second
	# one and not signing it would be the same defect, found the same way.
	codesign --force --timestamp --options runtime -i "${app_id}.profileverify" \
		-s "$updater_identity" "$root/Library/Application Support/Dsse/bin/dsse-profileverify"
	echo "==> signed the profile verifier"
elif [ "$app_kind" = "developer-id" ]; then
	echo "build_macos_ne_pkg: cannot sign the updater daemon — no identity resolved from the app's profile"
	exit 1
fi

# KeepAlive rather than a StartInterval schedule: the updater's own loop decides WHEN to act (device-local
# window, unattended, AC, wave, freeze), and a launchd schedule on top would be a second, dumber opinion about
# timing that nobody can see from the Console. launchd's job here is only to keep the process alive.
#
# ThrottleInterval bounds a crash loop: a daemon that dies instantly and is restarted instantly is a machine
# spending its battery on a fault nobody has noticed.
cat > "$root/Library/LaunchDaemons/${app_id}.updater.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>${app_id}.updater</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Library/Application Support/Dsse/bin/dsse-updater</string>
		<string>--loop</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>60</integer>
	<key>StandardOutPath</key><string>/Library/Application Support/Dsse/dsse-updater.log</string>
	<key>StandardErrorPath</key><string>/Library/Application Support/Dsse/dsse-updater.log</string>
</dict>
</plist>
PLIST

# A LaunchAgent in /Library/LaunchAgents runs for EVERY user at login (the lab's was per-user in ~/Library).
# It runs `open <app>` — deliberately not an on-demand VPN rule: an on-demand "connect" rule makes the OS treat
# the tunnel as mandatory and HOLD traffic while the provider starts or the Edge is unreachable (fail-close),
# and it resurrects the tunnel after --disable. See install_macos_ne_launchagent.sh for the full reasoning.
cat > "$root/Library/LaunchAgents/${app_id}.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>${app_id}</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/open</string>
		<string>/Applications/${app_exec}.app</string>
	</array>
	<key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST

# Persist GUI trust setup across logouts and reboots. A postinstall setenv alone
# belongs only to the current login session.
cp "$here/set_gui_trust_environment.sh" "$root/Library/Application Support/Dsse/bin/set-gui-trust-environment"
chmod 755 "$root/Library/Application Support/Dsse/bin/set-gui-trust-environment"
cat > "$root/Library/LaunchAgents/${app_id}.trust-environment.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${app_id}.trust-environment</string>
<key>ProgramArguments</key><array>
<string>/Library/Application Support/Dsse/bin/set-gui-trust-environment</string>
</array>
<key>RunAtLoad</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
PLIST

# ---- 3. scripts -------------------------------------------------------------------------------------------
# preinstall = the Windows CompatGate + MajorUpgrade downgrade guard.
cat > "$scripts/preinstall" <<'PRE'
#!/bin/sh
set -eu
APP="/Applications/__APP_EXEC__.app"
MIN_OS="__MIN_OS__"
NEW_BUILD="__BUILD__"
# The agent version THIS package installs, in the form the app reports it (CFBundleShortVersionString +
# CFBundleVersion). It is what a rollback authorisation has to name, so the two cannot drift: both are built
# from the same two values, here and in DsseDeviceHeartbeat.agentVersion().
AGENT_VERSION="__AGENT_VERSION__"
INTENT="/Library/Application Support/Dsse/rollback/rollback_intent.json"

# --- OS gate (CompatGate equivalent) ---
os="$(sw_vers -productVersion)"
lowest="$(printf '%s\n%s\n' "$os" "$MIN_OS" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)"
if [ "$lowest" != "$MIN_OS" ] && [ "$os" != "$MIN_OS" ]; then
	echo "This agent requires macOS $MIN_OS or later (found $os)." >&2
	exit 1
fi

# --- downgrade guard (MajorUpgrade equivalent) ---
# Installing an older build over a newer one leaves a System Extension whose version goes BACKWARDS; the
# activation request's replacement path then has to reason about a downgrade. Refuse it, as the MSI does.
#
# ★ WITH ONE WAY THROUGH, added 2026-08-11, because without it the guard was refusing the ONLY use of the
# rollback packages this same script stores. Every update was gated on restore material being present, that
# material was captured on every device — and installing it by hand hit this check and stopped. Material that
# nothing may install is not restore material.
#
# So the exception is not "allow downgrades", it is "allow the one downgrade an authorisation names". The
# authorisation (rollback_intent.json) is written by the root updater immediately before it launches this
# package, and it is refused unless it is owned by root, unreadable to anyone else, still inside its short
# validity window, and names EXACTLY the version this package installs. It is consumed on use, so it can never
# wave through a second install. An unintended downgrade is refused exactly as before — which is the whole
# point: an override that any install could take is not an override, it is a hole.
rollback_authorised() {
	[ -f "$INTENT" ] || return 1
	# Only root may author it. Without this check, anyone able to write the file could turn any downgrade into
	# an authorised one — and the file's whole job is to talk a root installer out of a safety check.
	owner="$(stat -f %u "$INTENT" 2>/dev/null || echo -1)"
	mode="$(stat -f %OLp "$INTENT" 2>/dev/null || echo 777)"
	[ "$owner" = "0" ] || { echo "  the rollback authorisation is not owned by root (uid $owner); ignoring it." >&2; return 1; }
	case "$mode" in
	600|400) ;;
	*) echo "  the rollback authorisation is mode $mode; only 600 or 400 is accepted." >&2; return 1 ;;
	esac
	# plutil parses JSON properly; `-lint` would treat this as a property list and reject valid JSON, which is
	# the mistake the agent-config gate below already documents.
	schema="$(plutil -extract schema raw -o - "$INTENT" 2>/dev/null || true)"
	to="$(plutil -extract to_version raw -o - "$INTENT" 2>/dev/null || true)"
	exp="$(plutil -extract expires_at_unix raw -o - "$INTENT" 2>/dev/null || true)"
	[ "$schema" = "dsse_rollback_intent.v1" ] || { echo "  the rollback authorisation has schema '$schema'; ignoring it." >&2; return 1; }
	# Seconds, compared as integers. A UTC timestamp handed to `date -j -f` would be read in local time, and a
	# guard that is wrong by the time-zone offset is wrong exactly when someone is travelling.
	case "$exp" in
	''|*[!0-9]*) echo "  the rollback authorisation has no usable expiry; ignoring it." >&2; return 1 ;;
	esac
	if [ "$(date -u +%s)" -ge "$exp" ]; then
		echo "  the rollback authorisation EXPIRED; deleting it and refusing." >&2
		rm -f "$INTENT" 2>/dev/null || true
		return 1
	fi
	[ "$to" = "$AGENT_VERSION" ] || {
		echo "  the rollback authorisation names '$to'; this package installs '$AGENT_VERSION'. Ignoring it." >&2
		return 1
	}
	return 0
}

if [ -d "$APP" ]; then
	cur="$(defaults read "$APP/Contents/Info.plist" CFBundleVersion 2>/dev/null || echo 0)"
	if [ "$cur" -gt "$NEW_BUILD" ] 2>/dev/null; then
		if rollback_authorised; then
			# Consumed here, before the install proceeds: single use, so an authorisation left behind by a
			# rollback that never completed cannot approve a downgrade tomorrow.
			rm -f "$INTENT" 2>/dev/null || true
			echo "Authorised ROLLBACK: installing $AGENT_VERSION (build $NEW_BUILD) over build $cur."
		else
			echo "A newer build ($cur) is already installed; refusing to downgrade to $NEW_BUILD." >&2
			echo "  A deliberate rollback is performed by the updater, which authorises itself:" >&2
			echo "    sudo '/Library/Application Support/Dsse/bin/dsse-updater' --rollback" >&2
			exit 1
		fi
	fi
fi

# --- ★ a PREVIOUS GENERATION under a different bundle id ---
#
# A bundle-id change makes this a different app: the old app's system extension and its transparent-proxy
# configuration survive this install untouched, and two providers then contend for the same traffic.
#
# REFUSED rather than cleaned up, deliberately. Only the OLD containing app can remove its own configuration
# and deactivate its own extension, and doing it in the wrong order leaves a proxy whose provider can never
# load — a machine with no connectivity at all. This package cannot do it correctly on the old app's behalf, so
# it says so instead of trying.
others="$(systemextensionsctl list 2>/dev/null | grep -F ".networkextension" | grep -F "activated" \
	| grep -v -F "__APP_ID__" | sed 's/^[[:space:]]*//' || true)"
if [ -n "$others" ]; then
	echo "" >&2
	echo "REFUSING TO INSTALL: another DSSE system extension is still active under a different bundle id." >&2
	printf '%s\n' "$others" | sed 's/^/  /' >&2
	echo "" >&2
	echo "Remove it with ITS OWN app first — only that app can take down its proxy configuration and extension," >&2
	echo "and the order matters (configuration, then deactivate, then delete):" >&2
	echo "  sudo /Library/Application\\ Support/Dsse/bin/dsse-uninstall     # if the previous generation shipped one" >&2
	echo "  # or, for an older build:  /Applications/<OldAgent>.app/Contents/MacOS/<OldAgent> --uninstall" >&2
	echo "" >&2
	exit 1
fi

# --- ★★★ COUNT THE EXTENSIONS WAITING TO UNINSTALL BEFORE ADDING ONE ---
#
# Every install retires the previous extension as "terminated waiting to uninstall on reboot", and NOTHING
# removes those but a reboot. Past a handful the new extension cannot come up cleanly: the tunnel goes
# connecting -> disconnected and the provider fails CLOSED, so every TCP connection on the machine dies while
# ICMP still answers. It does not look like a network outage — it looks like every program hung at once. On
# 2026-08-30 this Mac reached twenty-one and went dark with the operator's own session inside it; nothing
# remote could reach it and the way back was a reboot at the machine.
#
# ★★★ THIS GUARD EXISTED THAT SAME MORNING AND WAS PUT IN THE LAB'S PROVISIONING SCRIPT — a tool no customer
# receives. The package, which is the thing every customer actually runs, counted nothing; four hours later it
# installed onto a pile of four without a word. A protection that lives only in the harness protects only us.
#
# In preinstall, because refusing here leaves the machine exactly as it was.
pending_sx="$(systemextensionsctl list 2>/dev/null | grep -c 'waiting to uninstall' || true)"
if [ "${pending_sx:-0}" -ge 3 ]; then
	echo "" >&2
	echo "REFUSING TO INSTALL: $pending_sx system extensions on this Mac are waiting to uninstall on reboot." >&2
	echo "" >&2
	echo "  Adding another is how a Mac loses every network connection while still answering ping: past a" >&2
	echo "  handful of these the new extension cannot start, and this agent fails CLOSED when it cannot carry" >&2
	echo "  traffic. Nothing on screen would say why." >&2
	echo "" >&2
	echo "  RESTART THIS MAC and install again. One restart clears all of them at once; nothing else does." >&2
	echo "" >&2
	exit 1
elif [ "${pending_sx:-0}" -gt 0 ]; then
	echo "note: $pending_sx system extension(s) are waiting to uninstall on reboot; this install adds one more."
	echo "      Restart when convenient — at three this installer will refuse, because that is where the"
	echo "      extension stops coming up and the machine goes dark."
fi


# --- ★★★ THE CONFIGURATION MUST ALREADY BE HERE ---
#
# An agent installed without a configuration is not a partly-working agent. The provider starts, finds no
# agent_config, and fails its lifecycle (missing_agent_config_path) — while the transparent proxy configuration
# it created is already capturing this Mac's traffic. That is the macOS shape of the Windows blackhole: the
# steering is armed and the thing that was supposed to carry the traffic is not there. The user sees a machine
# that cannot reach anything, with a healthy install receipt and an approved system extension.
#
# So this is a PRECONDITION, not a step. Checked in preinstall, where refusing leaves the machine exactly as it
# was — a postinstall refusal would leave the payload on disk and a receipt claiming it.
#
# The configuration is supplied SEPARATELY from this package (an MDM drops it, an operator places it, or it
# travels beside the installer and is adopted below) which is also why the package itself can be distributed
# openly: without a config someone gives it, it installs nothing.
#
# ★ CONFIG_DIR IS DEFINED HERE, INSIDE THIS BLOCK, and the adoption that needs it comes after. The gate that
# proves this precondition (ops/checks/macos_installer_config_gate.sh) extracts from the marker line above and
# rewrites this one assignment to point at a fixture; a definition moved out of that range leaves the extracted
# gate with an unbound variable, and every case fails for a reason that has nothing to do with what it tests.
CONFIG_DIR="/Library/Application Support/Dsse"
CONFIG="$CONFIG_DIR/agent_config.json"
SCHEMA="__CONFIG_SCHEMA__"

# --- ★★★ THE ARTEFACTS MAY TRAVEL BESIDE THE PACKAGE (2026-08-30, operator directive) ---
#
# Until now the three things the customer downloads had to be in $CONFIG_DIR before this package would run —
# a directory Finder cannot write to. So every install, on every machine, began with a terminal and sudo to
# copy three files into a root-only path. That was the largest piece of avoidable human work in the lane, and
# it was ours: the package refuses without a configuration (for good reason, below), and offered no way to
# hand it one except by hand, as root, first.
#
# Nothing per-device can be baked INTO this package — it is signed and notarized, and a per-device edit breaks
# both. So the artefacts travel NEXT TO it, and this adopts them. One mechanism serves both shapes the
# operator asked for:
#   • one download   — an archive holding the signed installer and this device's three artefacts; the person
#                      unarchives it and double-clicks, and everything is already side by side.
#   • three downloads — the profile, the key and the approval fetched separately into the same folder as the
#                      installer they were issued for.
# Either way: no terminal, no sudo, no root-only path. The one Apple click that remains (approving the system
# extension) is removed only by an MDM system-extension-policy payload — see build_macos_mdm_profile.sh.
#
# ★ IT NEVER OVERRIDES WHAT IS ALREADY HERE. A machine an MDM has configured, or one an operator placed files
# on deliberately, has answered this question already; a package that adopts whatever happens to sit in
# Downloads on top of that would re-point a managed device from a folder. Absent means "adopt", present means
# "somebody already answered".
#
# ★ AND ADOPTION IS NOT TRUST. What is copied here is checked in postinstall exactly as before: the profile is
# verified against the key beside it before one field is read, and with no key nothing is derived and the
# device stays inert. This moves WHERE the artefacts are picked up, not WHETHER they are proven.
# dsse_profile_tenant reads the organization out of a signed profile without verifying it. The signature is
# checked later by the derivation; here the question is only "is this the same organization", and a wrong
# answer costs a preserved-or-moved file rather than trust.
dsse_profile_tenant() {
	[ -f "${1:-}" ] || return 0
	/usr/bin/python3 - "$1" <<'PYEOF' 2>/dev/null || true
import base64, json, sys
try:
    env = json.load(open(sys.argv[1]))
    body = json.loads(base64.b64decode(env["payload_b64"]))
    print((body.get("tenant_id") or (body.get("organization") or {}).get("tenant_id") or "").strip())
except Exception:
    pass
PYEOF
}

adopt_artefacts_from_beside_the_package() {
	pkg_path="${1:-}"
	[ -n "$pkg_path" ] || return 0
	beside="$(dirname "$pkg_path")"
	[ -d "$beside" ] || return 0
	[ -f "$beside/install_profile.json" ] || return 0
	mkdir -p "$CONFIG_DIR"

	# ★★★ A MACHINE THAT ALREADY HOLDS A PROFILE IS THE ORDINARY CASE, NOT A REASON TO IGNORE THE OPERATOR
	# (2026-08-31, measured — this installer re-armed a Mac against a deployment that had been destroyed the
	# night before).
	#
	# This used to adopt only onto a machine with NEITHER a configuration NOR a profile. But `dsse-uninstall`
	# deliberately keeps the configuration directory, and any Mac that has ever run this agent has one. So the
	# operator put today's four artefacts beside the package, ran it, saw "The upgrade was successful", and the
	# device kept YESTERDAY's profile: the wrong organization, a dead door, a used token — and postinstall
	# went on to install the interception root named in that old profile, so the machine was taught to trust a
	# root whose deployment no longer exists and whose key is now just a file somewhere. Nothing said a word.
	#
	# Putting a profile next to an installer and running it is a deliberate act. When the two profiles are the
	# same file, this is a re-install and there is nothing to do. When they differ, the one the operator just
	# handed the machine wins — and what was here is moved aside, by name, never deleted.
	if [ -f "$CONFIG_DIR/install_profile.json" ] \
	   && cmp -s "$beside/install_profile.json" "$CONFIG_DIR/install_profile.json"; then
		return 0   # the same profile: a re-install, nothing to adopt
	fi
	if [ -f "$CONFIG_DIR/install_profile.json" ] || [ -f "$CONFIG_DIR/agent_config.json" ]; then
		stamp="$(date -u +%Y%m%dT%H%M%SZ)"
		echo "==> this Mac already held a configuration, and a DIFFERENT profile was placed beside this"
		echo "    installer. The one beside the installer is what somebody just handed this machine, so it"
		echo "    wins. What was here is kept, renamed, not deleted:"
		# ★★★ A DIFFERENT PROFILE IS NOT ALWAYS A DIFFERENT DEPLOYMENT (2026-08-31). Changing an
		# organization's POSTURE re-issues its profile: same organization, same authorities, same door, one
		# field different. Moving the enrolment material aside for that discards an identity the Edge still
		# knows, and the device then meets "already enrolled under this name" and stands aside — an operator
		# who changed a setting has un-enrolled their fleet. The Windows side hit exactly this today and wrote
		# the rule down: on a same-organization profile replacement, do not touch the enrolment material.
		#
		# So what moves aside depends on whether the ORGANIZATION changed, which the profile states.
		beside_tenant="$(dsse_profile_tenant "$beside/install_profile.json")"
		here_tenant="$(dsse_profile_tenant "$CONFIG_DIR/install_profile.json")"
		replaced="install_profile.json agent_config.json profile_signing_key.txt interception-root.pem applied_install_profile.json"
		if [ -n "$beside_tenant" ] && [ "$beside_tenant" = "$here_tenant" ]; then
			echo "      (the same organization: the device identity and its token are KEPT)"
		else
			replaced="$replaced enrolment_token.txt device_identity_pointer.json"
		fi
		for f in $replaced; do
			[ -f "$CONFIG_DIR/$f" ] || continue
			mv "$CONFIG_DIR/$f" "$CONFIG_DIR/$f.replaced-$stamp"
			echo "      $f -> $f.replaced-$stamp"
		done
		# ★ AND THE ROOT THE PREVIOUS DEPLOYMENT WAS TRUSTED UNDER GOES WITH IT. Leaving it is a machine that
		# accepts, for every name on the internet, a certificate signed by an authority this device is no
		# longer part of. Removed by FINGERPRINT, read from the certificate this package itself installed.
		old_root="$CONFIG_DIR/interception-root.pem.replaced-$stamp"
		if [ -f "$old_root" ]; then
			old_sha="$(openssl x509 -in "$old_root" -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//; s/://g')"
			if [ -n "$old_sha" ] && security delete-certificate -Z "$old_sha" /Library/Keychains/System.keychain >/dev/null 2>&1; then
				echo "      and stopped trusting the previous deployment's interception root"
			fi
		fi
	fi
	echo "==> taking the device's configuration from the folder this installer was opened from:"
	echo "    $beside"
	cp "$beside/install_profile.json" "$CONFIG_DIR/install_profile.json"
	chmod 644 "$CONFIG_DIR/install_profile.json"
	echo "    install_profile.json      the signed profile"
	if [ -f "$beside/profile_signing_key.txt" ]; then
		cp "$beside/profile_signing_key.txt" "$CONFIG_DIR/profile_signing_key.txt"
		chmod 644 "$CONFIG_DIR/profile_signing_key.txt"
		echo "    profile_signing_key.txt   the key that verifies it"
	fi
	# The one-time approval is a credential: it lands mode 600, and a trailing newline from a browser download
	# would otherwise be sent as part of the token.
	if [ -f "$beside/enrolment_token.txt" ]; then
		tr -d '\n\r' < "$beside/enrolment_token.txt" > "$CONFIG_DIR/enrolment_token.txt"
		chmod 600 "$CONFIG_DIR/enrolment_token.txt"
		echo "    enrolment_token.txt       this device's one-time approval"
	fi
}
adopt_artefacts_from_beside_the_package "${1:-}"

refuse() {
	echo "" >&2
	echo "REFUSING TO INSTALL: $1" >&2
	echo "" >&2
	echo "  expected: $CONFIG" >&2
	echo "" >&2
	echo "  This agent steers all of this Mac's traffic. Installed without a usable configuration it would" >&2
	echo "  capture that traffic and have nowhere to send it, so the Mac would lose connectivity while every" >&2
	echo "  installation indicator reported success." >&2
	echo "" >&2
	echo "  Give it one of these and open this installer again — any of the three works:" >&2
	echo "    • put the files the Console issued for this device in the SAME FOLDER as this installer" >&2
	echo "      (install_profile.json, profile_signing_key.txt, enrolment_token.txt) — nothing else to do;" >&2
	echo "    • download the one archive the Console offers for this device, which holds all of them already;" >&2
	echo "    • or let an MDM deliver the configuration." >&2
	echo "" >&2
	exit 1
}

# ★★★ A PROFILE IS A CONFIGURATION (2026-08-29). The customer receives the package, the signed profile from
# the Console, and a one-time token; postinstall derives agent_config.json from the first two. Requiring the
# derived file HERE would refuse every install that follows the documented path, because the file it demands
# does not exist until this package creates it.
#
# The precondition is unchanged in substance: this Mac must have been told where to send traffic before
# steering is armed. It is now satisfied by either answer.
if [ ! -f "$CONFIG" ] && [ -f "$CONFIG_DIR/install_profile.json" ]; then
	if [ ! -f "$CONFIG_DIR/enrolment_token.txt" ]; then
		refuse "the install profile is here and the one-time enrolment token is not, so this device has nothing to enrol with. The token is shown once, on the Console screen that approved this device."
	fi
	echo "The configuration will be derived from the install profile."
	exit 0
fi
[ -f "$CONFIG" ] || refuse "the agent configuration is not on this Mac, and neither is an install profile to derive one from. Download the profile from the Console (Device configuration -> Make the configuration -> Download), place it at $CONFIG_DIR/install_profile.json with the one-time token beside it at $CONFIG_DIR/enrolment_token.txt, and install again."

# ★ NOT `plutil -lint`: it lints as a PROPERTY LIST, so it rejects perfectly good JSON with the same message it
# gives for corrupt JSON. A check that cannot tell "valid" from "broken" is worse than no check. `-convert`
# parses JSON properly, and `-extract` below reads it.
plutil -convert xml1 -o /dev/null "$CONFIG" 2>/dev/null || refuse "the agent configuration is not valid JSON."

cfg() { plutil -extract "$1" raw -o - "$CONFIG" 2>/dev/null || true; }

# ★ THESE CONDITIONS ARE READ OFF A DEPLOYED MAC, NOT OFF THE PUBLISHER (corrected 2026-08-11).
#
# The first version of this gate was written from the control plane's snapshot publisher — the shape that code
# EMITS — and it refused a healthy machine. Run against the real configuration of a Mac that was steering and
# inspecting perfectly, it stopped at "no schema_version", because the deployed file has none and nothing in the
# provider reads one from it. It also demanded transport.transport_tls_url; the key is
# network_extension_transport.transport_tls_url, and edge_url turned out to be the runtime-copy diagnostic
# endpoint (plain http to a lab port), not the path this Mac's traffic travels.
#
# A precondition invented from a model refuses every real install, at the one moment nothing else can proceed.
# So each check below names the field the PROVIDER actually reads, and was verified against a live device with
# deploy/reference/inspect_agent_config.sh.
#
# schema_version is deliberately NOT required: it does not appear in a deployed config and DsseAppProxyProvider
# never reads one from this file. If a future config carries one, the mismatch is worth catching, so it is
# checked only when present.
got_schema="$(cfg schema_version)"
if [ -n "$got_schema" ] && [ "$got_schema" != "$SCHEMA" ]; then
	refuse "the agent configuration is schema '$got_schema'; this build reads '$SCHEMA'."
fi

# The runtime-copy endpoint the provider dials (DsseFlowCopyRuntimeDriver reads edge_url). Empty means an agent
# with nowhere to report. It is NOT the traffic path — that is the transport below — so its scheme is not
# policed here; an earlier version refused plain http on this key and would have blocked every current device.
[ -n "$(cfg edge_url)" ] || refuse "the agent configuration names no edge_url."

# ★ THE TRAFFIC PATH. network_extension_transport.transport_tls_url is what the (T) tunnel dials, and
# DsseTransportSecurity treats its absence as "the transport is not configured at all". Without it the provider
# still creates the transparent proxy — so the Mac's traffic is captured with no tunnel to carry it.
[ -n "$(cfg network_extension_transport.transport_tls_url)" ] || refuse \
	"the agent configuration has no network_extension_transport.transport_tls_url, so the provider would capture this Mac's traffic with no tunnel to carry it."

# ★★★ THE UPDATE-SIGNING KEYS. Without them this Mac can never be updated.
#
# The updater daemon this package installs verifies the update manifest against pinned Ed25519 keys. Shipped
# without any, it starts, evaluates every 30 minutes, and reports on every pass that it can never update — into
# a root-only log nobody reads. That is what the fleet was actually carrying: a security agent with a fully
# built auto-update mechanism and no way to ever patch it. A device you cannot patch is the one an advisory is
# eventually written about.
#
# So the keys are part of "the configuration is present", exactly like the edge and the transport.
keycount() { plutil -extract "$1" raw -o - "$CONFIG" 2>/dev/null | head -1; }
keyat() { plutil -extract "$1.$2" raw -o - "$CONFIG" 2>/dev/null; }

read_keys() { # field -> prints one lowercase key per line; returns 1 if unusable
	_n=0
	while :; do
		# ★ `|| true` is load-bearing. Under `set -e`, a command substitution that fails inside an assignment
		# aborts the shell — so walking off the end of the array killed the loop before the `break` below,
		# and read_keys returned failure for EVERY config, including correct ones.
		_k="$(keyat "$1" "$_n" || true)"
		[ -n "$_k" ] || break
		_k="$(printf '%s' "$_k" | tr 'A-F' 'a-f')"
		# ★ TWO SHAPES, because the verifier accepts two. Ed25519 is 32 bytes (64 hex); ECDSA-P256 is an
		# uncompressed point, 65 bytes (130 hex) beginning 04 — which is what the config-signing key became when
		# it moved into the HSM. An earlier version of this check allowed only the first, and the effect was not
		# a rejected install: it silently discarded the key actually in force. A validator stricter than the
		# verifier refuses what the system can handle, quietly.
		# Pinned to agentpolicy.IsAcceptedPublicKeyHex by TestInstallerKeyShapesMatchTheVerifier.
		case "$_k" in *[!0-9a-f]*) return 1 ;; esac
		_len="$(printf '%s' "$_k" | wc -c | tr -d ' ')"
		case "$_len:$_k" in
		64:*) : ;;
		130:04*) : ;;
		*) return 1 ;;
		esac
		echo "$_k"
		_n=$((_n + 1))
	done
	[ "$_n" -gt 0 ] || return 1
	return 0
}

update_keys="$(read_keys update_signing_keys)" || refuse \
	"the agent configuration has no usable update_signing_keys, so this Mac could never be updated. Each entry must be a 64-character hex Ed25519 public key."

# ★ THE ORGANIZATION'S OWN TRUSTED AUTHORITIES (2026-08-16). The decision is that an agent's trusted CA bundle
# differs per organization and is fixed HERE, at install, so a device's trust is a property of the artifact it
# was installed from rather than of something fetched later. The configuration now carries it
# (trusted_ca_bundle), written by the Edge from the anchor actually in force.
#
# WARNS RATHER THAN REFUSES, deliberately and temporarily. Every configuration already on a Mac predates the
# field, so a hard requirement today would refuse every install on the fleet — which is precisely the mistake
# this file records twice already: a precondition written from what the code EMITS, refusing healthy machines.
# It becomes a refusal once configurations carrying it are the ones in the field.
#
# What IS refused is a bundle that is present and wrong. An empty or malformed authority in the field an
# installer reads is worse than an absent one: absent is handled by the existing manual step, present-and-wrong
# is a machine that trusts a certificate nobody signs under.
bundle_tenant="$(cfg trusted_ca_bundle.tenant_id)"
bundle_root="$(cfg trusted_ca_bundle.interception_root_pem)"
if [ -n "$bundle_tenant" ] || [ -n "$bundle_root" ]; then
	case "$bundle_root" in
	*"BEGIN CERTIFICATE"*) : ;;
	*) refuse "the agent configuration carries a trusted_ca_bundle whose interception_root_pem is not a certificate. This Mac would be installed pinned to nothing." ;;
	esac
	[ -n "$bundle_tenant" ] || refuse \
		"the agent configuration carries an interception root with no trusted_ca_bundle.tenant_id, so nothing records WHICH organization this Mac belongs to."
else
	echo "NOTE: this configuration carries no trusted_ca_bundle, so the interception root must still be placed" >&2
	echo "      on this Mac by hand or by MDM. Configurations written by a current Edge carry it." >&2
fi

# ★★ WHO MAY BUILD THE PACKAGES THIS MAC INSTALLS (2026-08-13, docs/2026-08-13_agent_publish_authority_design.ja.md).
#
# The keys above say WHICH VERSION may be installed. They do not say who built it, and until this field existed
# the answer was "anybody who can sign a manifest" — `installer -pkg -target /` as root does not check a
# package's signature, so holding the update key was equivalent to root on every Mac in the fleet. The operator
# declined two-person publishing approval, and this is what stands in its place: the update key is in the
# control plane's HSM and the Developer ID certificate is not, so a compromised control plane can only ever
# choose among versions this publisher really built.
#
# REQUIRED, not optional. The check costs nothing on a device that has it and is invisible on a device that does
# not, and "invisible when absent" is precisely the property that let the previous generation of this defect
# ship. Devices already in the field without the field keep updating (updateplatform.VerifyPublisher treats an
# absent requirement as a stated gap rather than a refusal) — but nothing NEW installs without one.
team_id="$(cfg update_publisher_team_id)"
[ -n "$team_id" ] || refuse \
	"the agent configuration names no update_publisher_team_id. Without it this Mac installs whatever a signed manifest points at, as root, without checking who built it — and the Apple Developer ID signature the packages already carry goes unused."
case "$team_id" in
*[!0-9A-Za-z]* | "") refuse "update_publisher_team_id '$team_id' is not an Apple Team ID (letters and digits only)." ;;
esac
if [ "${#team_id}" -ne 10 ]; then
	# A typo cannot match any certificate, so it would refuse every package including the right one — with a
	# message about signatures rather than about the typo.
	refuse "update_publisher_team_id '$team_id' is ${#team_id} characters; an Apple Team ID is 10."
fi
# ★ THE PLAN KEY IS NOT CHECKED HERE, and that is deliberate.
#
# The rollout plan is signed by the agent-policy key. The network extension already reads that key from
# network_extension_agent_policy_signing_public_key — its provisioned pin — and also accepts any key adopted
# from a signed trust bundle. The updater now reads the same union. There is nothing extra for an operator to
# supply, so there is nothing here to demand: a second field for one fact is a way for the two to disagree, and
# an earlier version of this gate invented exactly that.
plan_keys="$(cfg network_extension_agent_policy_signing_public_key)"

# ★ The two authorities must be different keys. The update key says WHAT code runs; the plan key says WHEN, and
# carries the halt. One key for both means the party a freeze exists to stop is the party who signs the freeze.
for u in $update_keys; do
	[ "$u" != "$(printf '%s' "$plan_keys" | tr 'A-F' 'a-f')" ] || refuse \
		"an update_signing_keys entry is the same key as the agent-policy signing key. The key that authorises RUNNING CODE must not also sign the policy and the rollout plan that can lift a freeze."
done

# ★ THE CONFIGURATION NOW AUTHORISES CODE EXECUTION, so who may write it matters in a way it did not before.
# A config an unprivileged user can edit is a config that user can point at their own update key.
owner="$(stat -f '%u' "$CONFIG" 2>/dev/null || echo -1)"
[ "$owner" = "0" ] || refuse \
	"the agent configuration is not owned by root (uid $owner). It names the keys that authorise installing software on this Mac, so anyone who can write it can run code as root."
perm="$(stat -f '%Sp' "$CONFIG" 2>/dev/null || echo '')"
# -rw-r--r--  : 1 type, 2-4 owner, 5-7 group, 8-10 other. Group-write is column 6, other-write is column 9.
gw="$(printf '%s' "$perm" | cut -c6)"
ow="$(printf '%s' "$perm" | cut -c9)"
if [ "$gw" = "w" ] || [ "$ow" = "w" ]; then
	refuse "the agent configuration is group- or world-writable ($perm). It names the keys that authorise installing software on this Mac."
fi

# ★ The region preference, if stated, is validated HERE — at install, in front of the person who typed it.
# The provider deliberately does not die over a malformed preference (darkening a Mac over a performance hint
# trades a slow connection for none), so if it is not caught here it is never caught: the device silently falls
# back to picking a region by measured latency, which on similar links is jitter. Same reasoning as the Windows
# agent, which refuses at install for exactly this key.
prio_keys="$(plutil -extract network_extension_region_priority raw -o - "$CONFIG" 2>/dev/null || true)"
if plutil -extract network_extension_region_priority raw -o - "$CONFIG" >/dev/null 2>&1; then
	[ -n "$prio_keys" ] || refuse "network_extension_region_priority is present but empty — state a preference or remove the key."
	for region in $prio_keys; do
		v="$(plutil -extract "network_extension_region_priority.$region" raw -o - "$CONFIG" 2>/dev/null || true)"
		case "$v" in
		'' | *[!0-9]*) refuse "network_extension_region_priority.$region = '$v' — priorities must be whole numbers." ;;
		esac
		# ★ 0 is rejected BY NAME. Zero-based is the ordinary instinct for "first", and the ranking treats it as
		# last — so 'tokyo: 0' delivers the exact inverse of the intent, with a healthy log and a working tunnel
		# to the wrong PoP.
		[ "$v" -gt 0 ] 2>/dev/null || refuse \
			"network_extension_region_priority.$region = 0. Priority 1 is highest; 0 would rank $region LAST, the opposite of what it looks like."
	done
fi

# --- quit the running agent so its bundle can be replaced ---
# Deliberately NOT `--uninstall`: on an upgrade that would remove the transparent-proxy configuration and
# deactivate the extension, so the machine would drop steering mid-upgrade and need re-approval. Just quit; the
# new app's activation request replaces the extension in place (the delegate already answers .replace).
osascript -e 'quit app "__APP_EXEC__"' >/dev/null 2>&1 || true
sleep 2
exit 0
PRE

cat > "$scripts/postinstall" <<'POST'
#!/bin/sh
set -eu
APP="/Applications/__APP_EXEC__.app"
LABEL="__APP_ID__"
PLIST="/Library/LaunchAgents/${LABEL}.plist"
UPDATER_PLIST="/Library/LaunchDaemons/${LABEL}.updater.plist"
CONFIG_DIR="/Library/Application Support/Dsse"

# ★★★ THE PROFILE IS THE CONFIGURATION, AND THIS IS WHERE IT BECOMES ONE (2026-08-29, the operator's call:
# the profile and the package alone must be enough — nothing else assembled by hand on the device).
#
# What a customer receives is this package, the signed install profile downloaded from the Console, and a
# one-time enrolment token. Until now that was not enough: the device also needed an agent_config.json holding
# the anchor, the organization's device-CA pin, its interception root, the update pins and a steering-rules
# file — and NOTHING IN THE PRODUCT PRODUCED IT. The lab wrote it by hand with a script no customer receives,
# and the stated answer was "MDM drops it", which makes MDM a requirement rather than a convenience.
#
# The profile now carries those facts (installprofile.DeploymentSpec). This derives the device's configuration
# from it, so the operator places two files and installs.
#
# ★ IT NEVER OVERWRITES ONE THAT IS ALREADY THERE. A deployment that DOES use MDM has placed a configuration
# deliberately, and a package that replaces it on every update would undo an administrator's decision on a
# schedule. Absent means "derive it"; present means "somebody already answered this".
# dsse_profile_issued_at reads the profile's issued_at without verifying it — the signature is checked by
# the derivation itself; here it only identifies WHICH profile a configuration came from.
dsse_profile_issued_at() {
	[ -f "${1:-}" ] || return 0
	/usr/bin/python3 - "$1" <<'PYEOF' 2>/dev/null || true
import base64, json, sys
try:
    body = json.loads(base64.b64decode(json.load(open(sys.argv[1]))["payload_b64"]))
    print((body.get("issued_at") or "").strip())
except Exception:
    pass
PYEOF
}

derive_config_from_profile() {
	profile="$CONFIG_DIR/install_profile.json"
	config="$CONFIG_DIR/agent_config.json"
	token_file="$CONFIG_DIR/enrolment_token.txt"
	pin_file="$CONFIG_DIR/profile_signing_key.txt"
	[ -f "$profile" ] || return 0
	# ★★★ "ALREADY HERE" WAS ALSO "DERIVED BY AN OLDER PACKAGE" (2026-08-31). This returned whenever a
	# configuration existed, which is always after the first install. So a fix to what the derivation WRITES
	# could never reach a machine that already had one: today's posture keys were added, the package was
	# rebuilt and installed, and the device came up with the same configuration and the same missing keys.
	# The same shape as the control plane's repair this morning — an installer fix that cannot reach an
	# installed machine — one lane over.
	#
	# So the question is not "is there a configuration" but "was it derived from THIS profile by THIS
	# package". applied_install_profile.json records the answer; a configuration derived by a different build
	# is re-derived, and what was there is kept beside it.
	# ★ ITS OWN MARKER, not applied_install_profile.json — that one is written by the AGENT when it applies a
	# profile, so it says nothing about which package derived the configuration. Reading somebody else's
	# record as an answer to your own question is how the first version of this would have skipped forever.
	#
	# ★★★ AND THE TOKEN IS A THIRD INPUT (2026-09-01, measured on a real Mac against a live deployment).
	#
	# The marker held the profile and the build. The one-time enrolment token is neither, and it is the ONE
	# artefact that routinely changes on its own: it is consumed on first use, so a device whose first
	# enrolment did not complete needs a fresh one. The failure message this package prints says exactly what
	# to do —
	#
	#	Place it and re-run the installer; nothing else is needed.
	#
	# — and the re-run then found the same profile and the same build, skipped the derivation, and left the
	# SPENT token in agent_config.json. Measured: the control plane said "enrolment token has already been
	# used" while the token that had just been issued for that machine showed used_at=null. The device could
	# never enrol again, and the instruction the operator was following could never work.
	#
	# So the marker records the token too — as a digest, never the secret. A different token is a different
	# derivation, which is the whole question this marker exists to answer.
	marker="$CONFIG_DIR/derived_by.txt"
	token_digest="none"
	[ -f "$token_file" ] && token_digest="$(/usr/bin/shasum -a 256 "$token_file" 2>/dev/null | cut -c1-16)"
	want="$(dsse_profile_issued_at "$profile")|__BUILD__|$token_digest"
	have=""
	[ -f "$marker" ] && have="$(cat "$marker" 2>/dev/null)"
	if [ -f "$config" ] && [ "$want" = "$have" ]; then
		echo "postinstall: the configuration here was derived from this profile, this build and this token;"
		echo "  leaving it alone"
		return 0
	fi
	if [ -f "$config" ]; then
		mv "$config" "$config.rederived-$(date -u +%Y%m%dT%H%M%SZ)"
		echo "postinstall: re-deriving the configuration (it was written from a different profile, a different"
		echo "  build of this package, or a different enrolment token); the previous one is beside it"
	fi
	dsse_record_derivation() { printf '%s\n' "$want" > "$marker"; chmod 644 "$marker"; }
	[ -f "$token_file" ] || {
		echo "postinstall: $profile is here and $token_file is not — this device has nothing to enrol WITH." >&2
		echo "  The token is shown once, on the Console screen that approved this device. Place it and" >&2
		echo "  re-run the installer; nothing else is needed." >&2
		return 0
	}
	# ★★★ THE PROFILE DOES NOT SUPPLY THE KEY THAT PROVES THE PROFILE (2026-08-29). This function used to
	# decode payload_b64 without checking the signature at all, and then take
	# deployment.agent_policy_signing_public_key out of the decoded body and write it as this device's pin. So
	# a substituted profile, signed by whoever substituted it, verified perfectly — and the profile decides the
	# door, the anchors this device verifies that door against, which keys may sign its updates, and which
	# processes are exempt from steering. The signature was decoration.
	#
	# The decision (2026-08-29, the operator's, asked for by the Windows session which had refused to take the
	# same shortcut): the key travels BESIDE the token. It is a fourth artefact the operator places, because
	# placing it is an explicit act — the same reason the one-time token is placed rather than derived — and
	# one signed installer then serves every deployment.
	#
	# No key means NO CONFIGURATION IS DERIVED. That is the safe end: the device is installed and inert, which
	# is exactly where it was a moment ago, rather than steering under a profile nothing checked.
	if [ ! -f "$pin_file" ]; then
		echo "postinstall: $profile is here and $pin_file is not — nothing can verify the profile." >&2
		echo "  This is the deployment's profile-signing key, shown in the Console beside the profile itself." >&2
		echo "  It is placed the same way the enrolment token is placed. Without it the profile could name its" >&2
		echo "  own verifier, so nothing is derived and this device stays inert." >&2
		return 0
	fi
	verified="$CONFIG_DIR/.install_profile.verified.json"
	if ! "$CONFIG_DIR/bin/dsse-profileverify" -profile "$profile" -pin "$pin_file" > "$verified" 2>"$verified.err"; then
		echo "postinstall: the install profile did NOT verify against $pin_file:" >&2
		sed 's/^/  /' "$verified.err" >&2 || true
		rm -f "$verified" "$verified.err"
		return 0
	fi
	rm -f "$verified.err"
	chmod 600 "$verified" 2>/dev/null || true
	# ★ THE ERROR HANDLER CANNOT LIVE ON THE NEXT LINE. A heredoc body starts at the newline that ends the
	# line carrying `<<`, so `|| {` opening a brace group there put the handler INSIDE the python input and
	# left the shell without its closing brace: "syntax error: unexpected end of file", at install time, on a
	# package that signing, notarisation and Gatekeeper had all accepted.
	if ! /usr/bin/python3 - "$verified" "$token_file" "$config" "$CONFIG_DIR" "$pin_file" "$profile" <<'DERIVE'
import json, pathlib, sys, datetime

verified_path, token_path, out_path, config_dir, pin_path, profile_path = sys.argv[1:7]
# The VERIFIED payload, printed by dsse-profileverify. Never the envelope: decoding that here is what let a
# profile name its own verifier.
body = json.loads(pathlib.Path(verified_path).read_text())
dep = body.get("deployment") or {}
token = pathlib.Path(token_path).read_text().strip()
tenant = (body.get("organization") or {}).get("tenant_id") or body.get("tenant_id") or ""
door = body.get("transport_url") or ""
device = __import__("socket").gethostname().split(".")[0]
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

# The anchor is written beside the configuration, because the configuration REFERENCES it by path: a file
# only root can write, so that re-pointing this device means writing where only root can.
# ★★★ EVERY AUTHORITY THAT CAN SIGN WHAT THIS DEVICE WILL BE SERVED, IN ONE FILE (2026-08-29, measured on a
# real Mac). An organization with its own address on the Edges is served a certificate from its OWN transport
# CA, which the deployment root does not sign — so a device given only the deployment anchor and told to dial
# the organization's name fails the handshake, and enrolment reports a bare network error.
anchor_ref = ""
anchors = [a for a in ([dep.get("anchor_pem")] + list(dep.get("transport_anchors_pem") or [])) if (a or "").strip()]
if anchors:
    anchor_ref = str(pathlib.Path(config_dir) / "deployment-anchor.pem")
    pathlib.Path(anchor_ref).write_text("\n".join(a.strip() for a in anchors) + "\n")

# ★ STEER-ALL. default_action=tunnel with no exceptions is this product's principle, not a shortcut: a
# selective list is the foothold a ZTNA deployment must not give. The provider refuses to start without a
# rules file, and this is the only shape its validator accepts an empty list in.
rules_ref = "network_extension_steering_rules.json"
(pathlib.Path(config_dir) / rules_ref).write_text(json.dumps({
    "schema_version": "network_extension_steering_rules.v1",
    "tenant_id": tenant,
    "version": now,
    "source_protected_app_map": "steer-all: every flow is tunnelled except what the deployment excluded",
    "generated_at": now,
    "default_action": "tunnel",
    "rules": [],
}, indent=2) + "\n")

cfg = {
    "edge_url": door,
    "network_extension_transport": {
        "transport_tls_url": door,
        "mtls_required": True,
        "client_identity_common_name": device,
        "dns_over_tunnel_supported": True,
    },
    "enrolment": {
        "enrol_url": door.rstrip("/") + "/enroll",
        "device_id": device,
        "enrolment_token": token,
        "tenant": tenant,
    },
    # ★★★ WHERE A STEERED FLOW GOES (2026-08-29, measured on a real Mac: 95 flows steered, 95 failed, none
    # succeeded). The provider took every flow — decision=accepted action=tunnel — and then had nowhere to
    # send it: runtime_copy_endpoint_passthrough_decision=endpoint_not_configured, edgeTransportRequestFailed
    # on every one. A device that steers and cannot deliver is worse than one that does not steer: it is
    # fail-closed by accident, and the box goes dark for everything that is not excluded.
    #
    # These are the values the control plane's own snapshot publisher writes. They are the product's, not the
    # deployment's, so the derivation states them rather than asking the profile to carry a constant.
    "network_extension_runtime_copy_endpoint_path": "/network-extension/runtime-copy/round-trip",
    "network_extension_runtime_copy_session_endpoint_path": "/network-extension/runtime-copy/session",
    "network_extension_runtime_copy_transport_scope": "real_edge",
    # ★★★ AND THE TUNNEL IS ON (2026-08-29, measured on a real Mac). Without this line the extension falls back
    # to the half-duplex session path: 5-second deadlines per exchange, one request at a time. The device DID
    # intercept — a real certificate from the organization's own issuing CA was presented for example.com,
    # google and github — and then not one HTTP request completed. Chrome showed nothing at all; curl was 0/15;
    # the log said round_trip_timeout 82 times. The control plane's own publisher has written this constant
    # since the tunnel existed, with the reason beside it ("real sites heavy in images or streaming break"),
    # and this derivation — which exists precisely to state what the publisher states — was missing it.
    "network_extension_runtime_copy_tunnel_enabled": True,
    "network_extension_runtime_copy_edge_connector_realness": "over_the_wire_local",
    # (A runtime_config_requires_network_extension flag used to be written here too, mirrored from the control
    # plane's publisher. The macOS agent reads no such key under any spelling — found the first time
    # ops/checks/mac_agent_config_keys_exist.sh was pointed at this file, 2026-08-30 — so it is not written.)
    "network_extension_default_passthrough_domains_enabled": True,
    "network_extension_rules_ref": rules_ref,
    "network_extension_install_profile_signed_path": profile_path,
    "network_extension_self_exclusion_enabled": True,
}
if anchor_ref:
    cfg["network_extension_transport"]["pinned_ca_ref"] = anchor_ref
# Absent stays absent. A blank reads as configured, and the refusal that follows names a field that is
# present — which is how a device ends up refusing the identity it was correctly handed.
if (dep.get("device_ca_pin_sha256") or "").strip():
    cfg["enrolment"]["device_ca_pin_sha256"] = dep["device_ca_pin_sha256"].strip()
# ★ THE NAME THAT SELECTS THE ENROLMENT ROUTE. On a folded transport port the enrolment path is chosen BY the
# name in the ClientHello, so a device holding nothing must send its organization's — not the address it
# happens to dial.
_enrol_name = ((body.get("organization") or {}).get("enrolment_server_name") or "").strip()
if _enrol_name:
    cfg["enrolment"]["enrolment_server_name"] = _enrol_name
if anchors:
    # The enrol endpoint is reached under the organization's name too, so it is verified against the same set.
    cfg["enrolment"]["enrol_ca_pem"] = "\n".join(a.strip() for a in anchors) + "\n"
# ★ THE OPERATOR'S FILE, NOT THE PROFILE'S FIELD. They are the same key on a healthy install — the profile
# verified against this one — but only one of them is a fact the profile could not have chosen.
cfg["network_extension_agent_policy_signing_public_key"] = pathlib.Path(pin_path).read_text().strip()
if dep.get("update_signing_keys"):
    cfg["update_signing_keys"] = dep["update_signing_keys"]
if (dep.get("update_publisher_team_id") or "").strip():
    cfg["update_publisher_team_id"] = dep["update_publisher_team_id"].strip()
if dep.get("steer_exclusions"):
    cfg["network_extension_self_exclusion_source_app_signing_identifiers"] = dep["steer_exclusions"]
if dep.get("passthrough_domains"):
    cfg["network_extension_passthrough_domains"] = dep["passthrough_domains"]
# ★★★ THE POSTURE THE PROFILE ASKS FOR, WHICH NOTHING WAS CARRYING (2026-08-31, found by checking that the
# arming had taken effect BEFORE creating the condition that would fire it).
#
# A profile can say posture=fail-open, the control plane gates it behind an explicit acknowledgement, the
# Console asks for that acknowledgement — and on macOS the device came up with
#
#	fail_open_enable_requested=false fail_open_acknowledged=false fail_open_armed=false
#
# because NOTHING IN THE TREE derived these two keys from a profile. The field was accepted, gated, signed,
# shipped and ignored. An operator could choose the posture, be asked to acknowledge its risk, and have every
# macOS device silently do the opposite — with no line anywhere saying so.
#
# ★ This is a heavier shape than the 2026-07-17 finding it resembles. That one was "armed and never fires";
# this is "never armed at all", which is why that investigation could not find it: it was looking for the
# reason a fire did not happen, and the arming was assumed.
#
# BOTH keys, and only together: the provider requires the acknowledgement separately from the request, so
# deriving one without the other produces a device that asks for fail-open and is refused it — the same
# silent disagreement one layer down. The provider still decides whether to honour it, and still says so at
# start-up; this only makes the operator's choice reach the device.
_posture = (body.get("posture") or "").strip().lower()
if _posture:
    cfg["network_extension_posture"] = _posture
if _posture == "fail-open" and body.get("ack_failopen"):
    cfg["network_extension_lab_fail_open_when_region_blocked"] = True
    cfg["network_extension_fail_open_acknowledged"] = True
# ★★★ THE PIN IS A FINGERPRINT, AND THIS WROTE ONLY THE CERTIFICATE (2026-08-30, measured on a real Mac
# installed through the documented lane and nothing else). The provider reads
# `trusted_ca_bundle.interception_root_sha256`; this wrote `interception_root_pem` beside it and nothing else,
# so `installedInterceptionRootPin` returned nil and the device started with
# `interception_root_pin decision=no_pin enforce=false pinned=none`. JSONDecoder ignores the key it does not
# know, the file reads as complete, and the check that would have caught it looked only at keys spelled
# `network_extension_*` — so EVERY device installed this way has the interception-root pin silently off, and
# will accept interception by any authority its machine happens to trust.
#
# Both are written: the PEM is what a reader can inspect, the fingerprint is what the pin compares. The
# fingerprint is SHA-256 over the DER, lowercase hex without separators — the shape
# DsseSignedAgentPolicy.verifiedInterceptionRoots normalises the Edge's announcement to.
#
# `enforce` stays absent ON PURPOSE. Off unless the configuration says otherwise is the design
# (DsseInterceptionRootPin): arming a fail-closed check at install time would strand a fleet mid-rotation,
# when old and new roots are announced together. The operator arms it for a fleet that is ready.
_root_pem = (dep.get("interception_root_pem") or "").strip()
if _root_pem:
    import base64 as _b64, hashlib as _hash, re as _re
    cfg["trusted_ca_bundle"] = {"tenant_id": tenant, "interception_root_pem": dep["interception_root_pem"]}
    _first = _re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", _root_pem, _re.S)
    if _first:
        _der = _b64.b64decode("".join(_first.group(1).split()))
        cfg["trusted_ca_bundle"]["interception_root_sha256"] = _hash.sha256(_der).hexdigest()
    else:
        # Say it rather than write a bundle whose pin is silently missing — that is the defect being fixed.
        print("postinstall: the profile's interception_root_pem is not a certificate; no pin was derived",
              file=sys.stderr)

pathlib.Path(out_path).write_text(json.dumps(cfg, indent=2) + "\n")
print("postinstall: derived", out_path, "from the install profile")
DERIVE
	then
		echo "postinstall: could not derive a configuration from the profile" >&2
		return 0
	fi
	chown root:wheel "$config" 2>/dev/null || true
	chmod 600 "$config" 2>/dev/null || true
	# Only after the derivation has actually produced a configuration: a marker written before it would make
	# a failed derivation look like a completed one, and the next install would skip it.
	dsse_record_derivation
}

# ★ STASH THIS PACKAGE AS ROLLBACK MATERIAL, and FIRST — before anything else in this script.
#
# The position is deliberate and was a defect for one revision. This script runs under `set -eu`, so anything
# above the stash that can fail takes the stash with it — and the stash is declared NON-FATAL precisely
# because a box that cannot store rollback material should still get a working agent. Sitting downstream of a
# chown meant the opposite: a permissions hiccup would have silently produced an installed agent that can
# never update, with the reason two screens up in an installer log nobody reads.
#
# agentupdate.Run refuses to start an update when CaptureRestoreMaterial produces nothing, on the argument
# that an update which cannot be rolled back is the same as having no rollback. Nothing was putting packages
# anywhere for it to find, so that refusal would fire on every Mac forever — and it presents as "the updater
# is broken", not as "the installer never stashed".
#
# $1 is the full path to the .pkg being installed; the installer passes it. This is the only moment the
# package that produced THIS version is reliably on hand.
#
# THE KEY COMES FROM THE BINARY, not from two shell expressions reading CFBundle keys. The updater looks
# material up under the version the LIVE extension recorded, and both that and this come from
# DsseDeviceHeartbeat.agentVersion() — so they agree by construction rather than by a script and a Swift
# function staying in step. A mismatch here would be ErrNoMaterial on every device forever, while all the code
# is present and running.
#
# Non-fatal throughout: a box with no stashed package refuses future updates and says why, which is degraded
# but honest. Failing the install would turn "cannot roll back later" into "has no agent now".
stash_rollback() {
	pkg_path="$1"
	[ -f "$pkg_path" ] || { echo "postinstall: no package path passed; rollback material NOT stored" >&2; return 0; }
	ver="$("$APP/Contents/MacOS/__APP_EXEC__" --version 2>/dev/null | head -1 | tr -d ' \t\r')" || ver=""
	case "$ver" in
		""|*[!A-Za-z0-9.+_-]*)
			echo "postinstall: could not read a usable agent version (got '$ver'); rollback material NOT stored" >&2
			return 0
			;;
	esac
	dir="/Library/Application Support/Dsse/rollback"
	mkdir -p "$dir" || return 0
	# SYSTEM+admin only: this directory holds a package a future rollback installs with root privileges, and
	# the parent inherits nothing restrictive. Same reasoning as the Windows datadir hardening.
	chown root:wheel "$dir" 2>/dev/null || true
	chmod 750 "$dir" 2>/dev/null || true
	dst="$dir/dsse-agent-$ver.pkg"
	# ★ IDEMPOTENT ON CONTENT, NOT ON NAME (2026-08-11, brought over from the Windows side's rollbackstore.Stash,
	# which had already been corrected for exactly this and whose reasoning applies here unchanged).
	#
	# A version string is not a promise about bytes. DSSE_BUILD is normally a UTC timestamp, so two builds
	# usually differ — but it is an override, and a rebuild that pins it produces the SAME name over DIFFERENT
	# bytes. Returning early on the name means the store keeps the first ones, and a rollback then installs a
	# package that was never what this device was running: restore material that is a lie about its own version.
	#
	# Comparing digests keeps the property that mattered (identical bytes are not rewritten, so a repair or a
	# re-run is cheap) and drops the one that was false. Last install wins when they differ, because the last
	# install is what is running.
	if [ -f "$dst" ]; then
		if [ "$(shasum -a 256 "$dst" 2>/dev/null | awk '{print $1}')" = "$(shasum -a 256 "$pkg_path" 2>/dev/null | awk '{print $1}')" ]; then
			# ★ TOUCH IT, AND THIS IS NOT COSMETIC (2026-08-12, found on the lab device by reading --status).
			# The prune below keeps the newest THREE BY MTIME, on the stated reasoning that those are "the one
			# just installed and the one before it". Returning early without touching broke exactly that: a
			# ROLLBACK reinstalls a package whose bytes are already stored, so the version the device just went
			# back to keeps its ORIGINAL mtime and becomes the OLDEST entry — the first one pruned by the next
			# two updates.
			#
			# The lab device landed in precisely that state: running 0.2.7, rollback target 0.2.4, and the store
			# holding 0.2.5, 0.2.6 and 0.2.7. The one package that mattered was the one thrown away, and the
			# device only knew because --status checks the target against the store and said "★ NOTHING".
			#
			# mtime now means "when this package was last INSTALLED", which is what the prune was always
			# reading it as.
			touch "$dst" 2>/dev/null || true
			echo "postinstall: rollback material for $ver already stored"
			return 0
		fi
		echo "postinstall: rollback material for $ver differs from the stored copy; replacing it"
		# The marker describes BYTES. It is removed here and rewritten only if the replacement lands, so a
		# failed copy can never leave a marker vouching for a package that is no longer there.
		rm -f "$dst.accepts-rollback-intent" 2>/dev/null || true
	fi
	# Copy to a temp name in the SAME directory then rename: a killed installer must leave either the old state
	# or a complete file, never a half one under the real name — a torn package is restore material that fails
	# only when someone tries to roll back.
	tmp="$dir/.staging-$$.pkg"
	if cp "$pkg_path" "$tmp" 2>/dev/null && mv "$tmp" "$dst" 2>/dev/null; then
		chmod 640 "$dst" 2>/dev/null || true
		# ★ SAY THAT THIS PACKAGE CAN BE ROLLED BACK TO. The preinstall that honours a rollback authorisation is
		# the one inside THIS package, so a package built before the authorisation existed refuses the downgrade
		# no matter what the updater writes. The updater cannot tell from the outside — so the package states it
		# about itself, here, next to the bytes it describes. Without this the refusal arrives as an opaque
		# installer failure during the incident that made someone reach for a rollback.
		printf '%s\n' "dsse_rollback_intent.v1" > "$dst.accepts-rollback-intent" 2>/dev/null || true
		chmod 640 "$dst.accepts-rollback-intent" 2>/dev/null || true
		echo "postinstall: rollback material stored for $ver at $dst"
		# ★ AND KEEP THE DIRECTORY BOUNDED. Nothing else would ever remove these: a package is ~8 MB and a Mac
		# updating monthly for two years would keep every one of them. Measured on the lab device after a single
		# day of update work: ten packages, 78 MB.
		#
		# Newest THREE by modification time, which keeps the one just installed and the one before it — the two a
		# rollback can actually use. Deliberately not "keep the running version by name": the name is what this
		# just wrote, and a rule that reasons about names is the rule that kept the wrong bytes above.
		#
		# The marker goes with its package. A marker outliving the bytes it describes would vouch for a file that
		# is not there, and the updater would refuse with the wrong reason.
		# ★ AND NEVER PRUNE THE ONE A ROLLBACK WOULD USE. The mtime rule above is a heuristic about what is
		# probably useful; this is the fact. The journal names the version this device would come back to
		# (from_version), and a store that has pruned it leaves a device that BELIEVES it can roll back and
		# cannot — which is only discovered during the incident that made someone reach for it.
		#
		# Read with plutil, which is in the base system and parses JSON. Any failure here leaves keep_ver empty,
		# and the prune falls back to the mtime rule alone rather than refusing to bound the directory.
		keep_ver="$(plutil -extract from_version raw -o - \
			"/Library/Application Support/Dsse/update/journal.json" 2>/dev/null || true)"
		[ "$keep_ver" = "<stdin>" ] && keep_ver=""
		ls -t "$dir"/dsse-agent-*.pkg 2>/dev/null | tail -n +4 | while read -r old_pkg; do
			if [ -n "$keep_ver" ] && [ "$(basename "$old_pkg")" = "dsse-agent-$keep_ver.pkg" ]; then
				echo "postinstall: KEEPING $(basename "$old_pkg") — it is the version a rollback would install"
				continue
			fi
			rm -f "$old_pkg" "$old_pkg.accepts-rollback-intent" 2>/dev/null || true
			echo "postinstall: pruned old rollback material $(basename "$old_pkg")"
		done
	else
		rm -f "$tmp" 2>/dev/null || true
		echo "postinstall: could not store rollback material for $ver" >&2
	fi
}
stash_rollback "${1:-}"

# ★ AND THE CONFIGURATION, from the profile the operator placed. After the stash (which is non-fatal and must
# run first, see its note) and before anything starts: the provider reads this file the moment it comes up.
derive_config_from_profile

# ★★★ AND THE MACHINE MUST TRUST THE ROOT IT IS ABOUT TO BE INSPECTED UNDER (2026-08-30, measured on a real Mac
# installed through the documented lane and nothing else). Everything else worked — the extension came up, the
# device enrolled, the datapath carried full-duplex, and the Edge presented a chain from the organization's own
# issuing CA — and the Mac could not load a single page: `curl` 0/10 with "unable to get local issuer
# certificate", every browser the same. Only the processes the deployment excluded from steering still worked,
# which is what made it survivable.
#
# The root was in the profile and in the derived configuration. NOTHING PUT IT WHERE A TLS CLIENT LOOKS. The
# product's answer until now was an MDM certificate payload, which makes MDM a requirement — and the decision
# of 2026-08-29 is that MDM is optional and the lane is package + profile + key + token. So the package does
# it: it runs as root, and it has just verified the profile that announces the root.
#
# ★ ONLY A ROOT A VERIFIED PROFILE ANNOUNCES. Never a file lying beside the package, never an unverified
# envelope: "install this root" is the most dangerous sentence a package can obey, and the signature on the
# profile is what makes it answerable. If the profile does not verify, nothing is trusted and the device stays
# as it was.
trust_announced_interception_root() {
	profile="$CONFIG_DIR/install_profile.json"
	pin_file="$CONFIG_DIR/profile_signing_key.txt"
	[ -f "$profile" ] && [ -f "$pin_file" ] || return 0
	# derive_config_from_profile leaves this behind on the install that derived; a device whose configuration
	# was already present (MDM placed it) has none, so verify here rather than skip. Trust is not the
	# configuration and must not inherit "somebody already answered this".
	verified="$CONFIG_DIR/.install_profile.verified.json"
	if [ ! -f "$verified" ]; then
		verified="$(mktemp -t dsse-verified-profile)"
		if ! "$CONFIG_DIR/bin/dsse-profileverify" -profile "$profile" -pin "$pin_file" > "$verified" 2>/dev/null; then
			echo "postinstall: the install profile did not verify; no interception root was trusted" >&2
			rm -f "$verified"
			return 0
		fi
	fi
	root="$CONFIG_DIR/interception-root.pem"
	if ! /usr/bin/python3 - "$verified" "$root" <<'ROOT'
import json, pathlib, sys
body = json.loads(pathlib.Path(sys.argv[1]).read_text())
pem = ((body.get("deployment") or {}).get("interception_root_pem") or "").strip()
if not pem:
    sys.exit(1)          # a deployment that inspects nothing announces no root; that is not a failure
pathlib.Path(sys.argv[2]).write_text(pem + "\n")
ROOT
	then
		return 0
	fi
	chmod 644 "$root"

	# ★★★ THE VERB DEPENDS ON WHETHER THE CERTIFICATE IS SELF-SIGNED, AND THIS ALWAYS SAID trustRoot
	# (2026-09-04, measured on a real Mac against a deployment built from the published tree: Chrome showed a
	# certificate error on every page while this line reported success).
	#
	# `trustRoot` means "this is a root". What a deployment announces is usually NOT one: the interception CA
	# is issued by the deployment's own root, so it is an INTERMEDIATE, and macOS marked with trustRoot keeps
	# looking for the issuer above it, does not find it, and refuses the chain — CSSMERR_TP_NOT_TRUSTED —
	# while `security find-certificate` finds it and `openssl s_client` cheerfully prints its name. Every
	# symptom says installed; the browser says no. The verb for a certificate that is not self-signed is
	# `trustAsRoot`, and with it the same certificate verifies.
	#
	# So the certificate decides, because the certificate knows: subject == issuer or it does not.
	subject="$(openssl x509 -in "$root" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
	issuer="$(openssl x509 -in "$root" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')"
	if [ -n "$subject" ] && [ "$subject" = "$issuer" ]; then verb="trustRoot"; else verb="trustAsRoot"; fi

	# Idempotent: adding a certificate that is already trusted succeeds and changes nothing, so a reinstall or
	# an update does not accumulate anything. -d puts it in the admin domain (System keychain), which is where
	# every TLS client on the machine looks; a user-domain trust would leave root-owned daemons failing.
	if ! security add-trusted-cert -d -r "$verb" -p ssl -k /Library/Keychains/System.keychain "$root" >/dev/null 2>&1; then
		# ★ LOUD, because the shape of this failure is a device that steers perfectly and cannot load a page.
		echo "postinstall: COULD NOT TRUST the announced interception root — this device will steer traffic" >&2
		echo "  and then fail every HTTPS request with 'unable to get local issuer certificate'. Install it by" >&2
		echo "  hand before relying on this machine:" >&2
		echo "  sudo security add-trusted-cert -d -r $verb -p ssl -k /Library/Keychains/System.keychain '$root'" >&2
		return 0
	fi

	# ★★★ AND THE COMMAND SUCCEEDING IS NOT THE MACHINE TRUSTING IT. That is precisely how the wrong verb went
	# unnoticed: add-trusted-cert returned 0, this line printed success, and nothing on the device would load.
	# Read the trust settings back and say what is actually there.
	cn="$(printf '%s' "$subject" | sed 's/.*CN *= *//; s/,.*//')"
	if security dump-trust-settings -d 2>/dev/null | grep -qF "$cn"; then
		echo "postinstall: this machine now trusts the interception root its organization announced ($verb)"
	else
		echo "postinstall: the interception root was added and the trust store does not show it — this device" >&2
		echo "  will steer traffic and then fail every HTTPS request. Check:" >&2
		echo "  security dump-trust-settings -d" >&2
	fi
}
trust_announced_interception_root

# ★★★ AND THE KEYCHAIN IS NOT THE ONLY PLACE A TOOL LOOKS (2026-08-31, measured on a real Mac an hour after
# the root was installed correctly).
#
#	aws sts get-caller-identity
#	SSL validation failed … certificate verify failed: unable to get local issuer certificate
#
# The keychain held the root. The AWS CLI does not read the keychain: like most of the Python, Node, Go and
# curl-based tooling on a developer's machine, it carries its own CA file. So this device steered perfectly,
# every browser worked, and the command line broke — which is the shape an operator reports as "the agent
# broke my machine" with no idea what to look at.
#
# The Windows side already sets these variables; macOS never did, and the omission is invisible from inside a
# browser. So the deployment writes ONE bundle it owns — the system's own anchors plus the root its
# organization announced — and points the standard variables at it.
#
# ★ AND IT WRITES DOWN WHERE IT PUT THINGS. A root installed in more than one place can only be removed from
# the places somebody recorded; today both platforms found roots from deployments that no longer exist,
# surviving in stores nobody had thought to look in. The ledger is what dsse-uninstall reads.
install_the_trust_every_tool_actually_reads() {
	root="$CONFIG_DIR/interception-root.pem"
	[ -f "$root" ] || return 0
	bundle="$CONFIG_DIR/trusted_ca_bundle.pem"
	tmp="$bundle.new"
	# The system's own anchors first, so this bundle is a SUPERSET of what the machine already trusted. A
	# bundle holding only the interception root would make every tool that uses it reject the public internet.
	if ! security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > "$tmp" 2>/dev/null; then
		echo "postinstall: could not read this Mac's own trust anchors, so no tool bundle was written." >&2
		echo "  Command-line tools that do not read the keychain (aws, python, node, some curl builds) will" >&2
		echo "  fail every HTTPS request while this device is steered." >&2
		rm -f "$tmp"
		return 0
	fi
	anchors="$(grep -c 'BEGIN CERTIFICATE' "$tmp" 2>/dev/null || echo 0)"
	if [ "$anchors" -lt 50 ]; then
		echo "postinstall: only $anchors system anchors were readable — refusing to write a tool bundle that" >&2
		echo "  would make this machine distrust most of the internet." >&2
		rm -f "$tmp"
		return 0
	fi
	cat "$root" >> "$tmp"

	# ★★★ AND THE AUTHORITY ABOVE IT, OR EVERY OPENSSL-BASED TOOL STILL FAILS (2026-09-04, measured on a real
	# Mac against a deployment built from the published tree — this is what takes a developer's own tools off
	# the network the moment their machine is steered, while their browser keeps working):
	#
	#	node, bundle as written here   ERROR UNABLE_TO_GET_ISSUER_CERT
	#	node, bundle + deployment root status 404          (i.e. it reached the server)
	#
	# What a deployment announces as its interception root is usually an INTERMEDIATE — issued by the
	# deployment's own root. macOS can be told to treat an intermediate as an anchor (`-r trustAsRoot`, which
	# is why the browser works), but OpenSSL has no such thing: given a CA file it builds the chain until it
	# reaches a SELF-SIGNED certificate, and stops with UNABLE_TO_GET_ISSUER_CERT if it cannot. The
	# intermediate alone is not a chain; it is the middle of one.
	#
	# So the deployment's own anchor goes in beside it. It is already on the device — the profile carries it
	# and the installer wrote it — and it is what the interception root chains to.
	if [ -f "$CONFIG_DIR/deployment-anchor.pem" ]; then
		if ! grep -qF "$(head -2 "$CONFIG_DIR/deployment-anchor.pem" | tail -1)" "$tmp" 2>/dev/null; then
			cat "$CONFIG_DIR/deployment-anchor.pem" >> "$tmp"
		fi
	else
		echo "postinstall: no deployment anchor on this device, so the trust bundle ends at an intermediate —" >&2
		echo "  tools that build a chain to a self-signed root (node, python, aws, git) will still fail with" >&2
		echo "  UNABLE_TO_GET_ISSUER_CERT while this device is steered." >&2
	fi

	mv "$tmp" "$bundle"
	chmod 644 "$bundle"
	sha="$(openssl x509 -in "$root" -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//; s/://g')"
	printf '{"interception_root_sha1":"%s","installed_in":["System.keychain","%s","/etc/zshenv"]}\n' \
		"$sha" "$bundle" > "$CONFIG_DIR/trusted_roots_ledger.json"
	chmod 644 "$CONFIG_DIR/trusted_roots_ledger.json"
	echo "postinstall: wrote $bundle ($anchors system anchors + this organization's root and the deployment anchor it chains to)"

	# ★ THE VARIABLES, FOR SHELLS AND FOR GUI APPLICATIONS, BETWEEN MARKERS so removal is exact. Nothing else
	# in these files is touched, and an operator can read what was added.
	marker_begin="# >>> Lantern DSSE trust bundle >>>"
	marker_end="# <<< Lantern DSSE trust bundle <<<"
	if [ -f /etc/zshenv ]; then
		awk -v b="$marker_begin" -v e="$marker_end" '
			$0 == b { skip = 1 } !skip { print } $0 == e { skip = 0 }
		' /etc/zshenv > /etc/zshenv.dsse.new 2>/dev/null || cp /etc/zshenv /etc/zshenv.dsse.new
	else
		: > /etc/zshenv.dsse.new
	fi
	{
		printf '%s\n' "$marker_begin"
		printf '# Written by the Lantern DSSE agent installer. Tools that do not read the macOS keychain need\n'
		printf '# to be told where this deployment'"'"'s trust bundle is, or they fail every request while this\n'
		printf '# device is steered. Removed by dsse-uninstall.\n'
		for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS AWS_CA_BUNDLE; do
			printf 'export %s="${%s:-%s}"\n' "$v" "$v" "$bundle"
		done
		printf '%s\n' "$marker_end"
	} >> /etc/zshenv.dsse.new
	mv /etc/zshenv.dsse.new /etc/zshenv
	chmod 644 /etc/zshenv
	# ★★★ IN THE CONSOLE USER'S SESSION, NOT ROOT'S (2026-09-05, found when a Node application on a steered
	# Mac failed every request with "SSL certificate verification failed" while this line had reported
	# success). The postinstall runs as root, and `launchctl setenv` writes to the domain of whoever runs it —
	# so the variables landed in root's launchd session, which no GUI application inherits from. The message
	# below said "GUI apps immediately" and it was not true of any of them.
	#
	# The uninstaller in this same file already had the shape: `launchctl asuser <uid>` puts the command in
	# the logged-in user's session, which is where an application launched from the Dock or Spotlight reads
	# its environment.
	#
	# ★ NOTHING REACHES A PROCESS THAT IS ALREADY RUNNING. An application started before this install keeps
	# the environment it was started with, so it goes on not knowing where the bundle is until it is quit and
	# opened again. That is said out loud below rather than left for somebody to discover mid-session.
	gui_uid="$(stat -f %u /dev/console 2>/dev/null || echo 0)"
	for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS AWS_CA_BUNDLE; do
		launchctl setenv "$v" "$bundle" 2>/dev/null || true
		if [ "$gui_uid" != "0" ]; then
			launchctl asuser "$gui_uid" launchctl setenv "$v" "$bundle" 2>/dev/null || true
		fi
	done
	echo "postinstall: tools that carry their own CA file are pointed at it — new shells, and applications"
	echo "postinstall: launched from now on. Anything ALREADY RUNNING keeps the environment it started with:"
	echo "postinstall: quit and reopen it, or it will fail every TLS request while this device is steered."
}
install_the_trust_every_tool_actually_reads

# ★ SAY WHAT WAS EXPECTED BEFORE FAILING ON IT. Under `set -eu` a missing path used to abort here with
# `chown: … No such file or directory`, which `installer` renders to the operator as the generic "contact the
# manufacturer". The real cause on 2026-08-10 was app RELOCATION: PackageKit had installed the app into a copy
# it found elsewhere on the disk, so /Applications held nothing.
if [ ! -d "$APP" ]; then
	echo "postinstall: $APP is missing after the payload was written." >&2
	echo "  The usual cause is app RELOCATION: PackageKit installs into an existing copy of the same bundle id" >&2
	echo "  found elsewhere on the disk. Check: mdfind \"kMDItemCFBundleIdentifier == '__APP_ID__'\"" >&2
	echo "  This package is built non-relocatable, so seeing this means the package was not built by" >&2
	echo "  deploy/reference/build_macos_ne_pkg.sh." >&2
	exit 1
fi
chown -R root:wheel "$APP" "$PLIST"
chmod -R go-w "$APP"
chmod 644 "$PLIST"

# Load the login item and start the agent for the user actually installing, not for root. The agent must run in
# a GUI session: it owns the System Extension activation request (which needs user approval unless an MDM
# profile pre-approves it) and the OOB step-up browser hand-off, neither of which root can do.
# The updater daemon: root-owned, and loaded here rather than left for the next reboot. A device that took an
# install and then waits for a restart before it can ever be updated again is one more state to reason about.
chown root:wheel "$UPDATER_PLIST" "/Library/Application Support/Dsse/bin/dsse-updater" 2>/dev/null || true
chmod 644 "$UPDATER_PLIST" 2>/dev/null || true
chmod 755 "/Library/Application Support/Dsse/bin/dsse-updater" 2>/dev/null || true
launchctl bootout system "$UPDATER_PLIST" >/dev/null 2>&1 || true
launchctl bootstrap system "$UPDATER_PLIST" >/dev/null 2>&1 || \
	echo "postinstall: the updater daemon could not be loaded; this device will not update itself until it is" >&2

uid="$(stat -f %u /dev/console)"
if [ -n "$uid" ] && [ "$uid" != "0" ]; then
	launchctl bootout "gui/$uid/${LABEL}.trust-environment" >/dev/null 2>&1 || true
	launchctl bootstrap "gui/$uid" "/Library/LaunchAgents/${LABEL}.trust-environment.plist" >/dev/null 2>&1 ||
		echo "postinstall: GUI trust setup could not be registered for this session; it will run at the next login." >&2
	launchctl bootout "gui/$uid/$LABEL" >/dev/null 2>&1 || true
	# ★★★ AND THE PREVIOUS GENERATION HAS TO DIE FIRST (2026-08-30, measured: an install that changed nothing
	# on screen). `bootout` only reaches a process launchd started under this label — an agent launched by
	# `open` from an earlier provisioning survives it. `open` then finds a running app with this bundle id and
	# merely ACTIVATES it, so the binary that was just installed never runs, never submits the System Extension
	# activation request, and install_state.json says "system_extension_user_approval" forever with no request
	# for anyone to approve. Nothing anywhere says the app on disk is not the app in memory.
	pkill -x "__APP_EXEC__" >/dev/null 2>&1 || true
	i=0; while [ "$i" -lt 10 ] && pgrep -qx "__APP_EXEC__"; do sleep 1; i=$((i + 1)); done
	launchctl bootstrap "gui/$uid" "$PLIST" >/dev/null 2>&1 || true
	launchctl asuser "$uid" /usr/bin/open "$APP" >/dev/null 2>&1 || true
fi

# ★ "INSTALLED" AND "WORKING" ARE DIFFERENT FACTS, and the installer can only establish the first.
#
# The system extension needs a person to approve it in System Settings, which cannot happen inside postinstall.
# So this does not claim success — it records what is done, what is still pending, and how to check. One file,
# so an operator, an MDM and a monitor all read the same answer instead of three guesses.
#
# On 2026-08-10 the installer said "The install was successful" on a machine whose extension was unapproved and
# which, once approved, had no working HTTPS at all. Nothing on the device recorded that gap.
state="/Library/Application Support/Dsse/install_state.json"
pending='"system_extension_user_approval"'
if systemextensionsctl list 2>/dev/null | grep -F "__APP_ID__.networkextension" | grep -qF "[activated enabled]"; then
	pending=""
fi
ver="$("$APP/Contents/MacOS/__APP_EXEC__" --version 2>/dev/null | head -1 | tr -d ' \t\r')" || ver=""
cat > "$state" <<STATE
{
  "bundle_id": "__APP_ID__",
  "version": "${ver:-unknown}",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pending": [${pending}],
  "verify_with": "/Library/Application Support/Dsse/bin/dsse-verify-install",
  "uninstall_with": "/Library/Application Support/Dsse/bin/dsse-uninstall"
}
STATE
chmod 644 "$state" 2>/dev/null || true

if [ -n "$pending" ]; then
	echo ""
	echo "  INSTALLED, BUT NOT YET PROTECTING THIS DEVICE."
	echo "  Approve the system extension:  System Settings > General > Login Items & Extensions"
	echo "                                 > Network Extensions > enable \"__APP_EXEC__\""
	echo "  A notification's OK button dismisses it; it does not approve."
	echo "  Then verify:  sudo '/Library/Application Support/Dsse/bin/dsse-verify-install'"
	echo ""
fi
exit 0
POST

sed -i '' -e "s|__APP_EXEC__|${app_exec}|g" -e "s|__APP_ID__|${app_id}|g" \
          -e "s|__MIN_OS__|${min_os}|g" -e "s|__BUILD__|${build}|g" \
          -e "s|__AGENT_VERSION__|${version}+${build}|g" \
          -e "s|__CONFIG_SCHEMA__|${config_schema}|g" "$scripts/preinstall" "$scripts/postinstall"
# ★ No placeholder may survive substitution. An unreplaced __CONFIG_SCHEMA__ would make the gate compare the
# config against the literal string and refuse EVERY install — and the package would still build, sign and
# notarize cleanly, so the failure would first appear on a customer's Mac.
if grep -l '__[A-Z_]*__' "$scripts/preinstall" "$scripts/postinstall" >/dev/null 2>&1; then
	echo "build_macos_ne_pkg: a placeholder was not substituted in the install scripts:" >&2
	grep -Hn '__[A-Z_]*__' "$scripts/preinstall" "$scripts/postinstall" >&2
	exit 1
fi
chmod 755 "$scripts/preinstall" "$scripts/postinstall"

# ---- 4. component + product packages ----------------------------------------------------------------------
comp="$out/${app_exec}-component.pkg"
prod="$out/${app_exec}-${version}-${build}.pkg"
echo "==> pkgbuild"
# ★ NON-RELOCATABLE, and this is not a detail — it is the difference between installing the agent and
# installing it somewhere else entirely (2026-08-10).
#
# PackageKit's app-relocation looks for an existing copy of the payload's bundle identifier ANYWHERE on the
# disk and, finding one, installs there instead of at the payload path. The first Developer ID install of this
# package failed exactly that way:
#
#   PackageKit: Applications/LanternDsseAgent.app relocated to …/var/macos-ne-pkg-devid/app/LanternDsseAgent.app
#
# It found the BUILD OUTPUT and treated it as where the app lives. Nothing landed in /Applications and the
# postinstall then failed on a path that did not exist.
#
# On a customer's Mac the same feature is worse, because it usually SUCCEEDS: one forgotten copy in ~/Downloads,
# a Time Machine restore, a second admin's home directory — and the update installs there, leaving the agent in
# /Applications on the old version while every check that looks at the receipt says the install worked.
#
# The component plist is generated (--analyze) rather than hand-written so a bundle added later is covered
# instead of silently keeping the default.
#
# ★ AND NOT VERSION-CHECKED (2026-08-11, from a rollback that reported success and did nothing).
#
# `--analyze` defaults BundleIsVersionChecked to true, which puts the app in PackageInfo's <bundle-version>
# and tells PackageKit to compare bundles and skip the payload when the installed one is newer. Measured on a
# live Mac while rolling 0.2.3 back to 0.2.2:
#
#   ./preinstall: Authorised ROLLBACK: installing 0.2.2+… over build 20260811052447.
#   PackageKit: Skipping component "jp.co.lantern-networks.dsse.agent" (0.2.2-…) because the version
#               0.2.3-… is already installed at /Applications/LanternDsseAgent.app.
#
# The authorisation was written, read, accepted and consumed; the postinstall ran; a receipt was written;
# `installer` said "The upgrade was successful" — and the app on disk was still 0.2.3. A silent no-op wearing
# a success message, which is the worst outcome available.
#
# THE POINT IS NOT THAT THE CHECK IS WRONG. It is that there were TWO layers deciding whether a downgrade may
# happen, and only one of them can be told that this one was authorised. A guard that cannot hear the exception
# does not protect the fleet, it just makes the recovery path fail in a way nobody can read. So the decision
# lives in exactly one place — the preinstall, which refuses an unauthorised downgrade and consumes a
# single-use authorisation for the one it allows — and PackageKit is left to apply payloads.
# ★★★ THE SCRIPTS MUST PARSE, AND NOTHING WAS ASKING (2026-08-29, measured: a package shipped whose
# postinstall ended with "syntax error: unexpected end of file"). pkgbuild does not read them, productbuild
# does not read them, `codesign` signs them, the notary service accepts them and Gatekeeper says "accepted" —
# every check this lane has said yes to a script the shell cannot run, and the first thing that noticed was a
# real Mac, at install time, with the payload already refused.
#
# The failure was a heredoc that swallowed its own error handler, which is exactly the kind of thing a parse
# check catches for free and no amount of signing ever will.
for script in "$scripts"/*; do
	[ -f "$script" ] || continue
	sh -n "$script" || { echo "the generated $(basename "$script") does not parse — refusing to build a package whose scripts cannot run" >&2; exit 1; }
	echo "  ok: $(basename "$script") parses"
done

# ★★★ THE POSTINSTALL MUST NOT BE ABLE TO TRUST A PROFILE ON THE PROFILE'S OWN WORD (2026-08-29). It used to
# decode payload_b64 directly and lift the verifying key out of the decoded body, so a substituted profile
# proved itself. A comment saying not to do that again is not a check; this is. Both halves are asserted,
# because either one alone is satisfiable by the broken version: it must CALL the verifier, and it must not
# reach into the envelope behind its back.
if ! grep -q "dsse-profileverify" "$scripts/postinstall"; then
	echo "the generated postinstall does not run the profile verifier — refusing to build a package that would" >&2
	echo "  derive a device's configuration from a profile nothing checked" >&2
	exit 1
fi
if grep -q 'b64decode(env\["payload_b64"\])' "$scripts/postinstall"; then
	echo "the generated postinstall decodes the profile envelope itself — that is the path that let a profile" >&2
	echo "  name the key it is verified against. Derive from the VERIFIED payload instead." >&2
	exit 1
fi
echo "  ok: postinstall verifies the profile before deriving from it"

# ★★★ THE EXIT MUST NOT ASK ROOT WHETHER THERE IS A CONFIGURATION (2026-08-29). Both halves are asserted
# because either alone is satisfied by the broken version: the removal step must run as the console user, and
# a failure of that step must STOP the uninstall rather than proceed to delete the app.
uninst="$root/Library/Application Support/Dsse/bin/dsse-uninstall"
if ! grep -q 'launchctl asuser' "$uninst"; then
	echo "the generated dsse-uninstall runs the app as root to remove the transparent proxy configuration —" >&2
	echo "  root is shown an empty preference list, so it would report success and then strand the machine" >&2
	exit 1
fi
if grep -q 'the app reported a problem; continuing' "$uninst"; then
	echo "the generated dsse-uninstall continues after the configuration removal fails — that deletes the only" >&2
	echo "  thing that can remove a proxy configuration which is still capturing traffic" >&2
	exit 1
fi
echo "  ok: dsse-uninstall removes the configuration as the console user, and stops if that fails"

python3 "$here/verify_generic_payload.py" "$root" --app-id "$app_id" --app-exec "$app_exec" \
	--extension-exec "${DSSE_SYSEXT_EXEC:-DsseAppProxyProvider}"

pkgbuild --analyze --root "$root" "$out/component.plist" >/dev/null
n_bundles="$(plutil -convert json -o - "$out/component.plist" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"
i=0
while [ "$i" -lt "$n_bundles" ]; do
	plutil -replace "$i.BundleIsRelocatable" -bool NO "$out/component.plist"
	plutil -replace "$i.BundleIsVersionChecked" -bool NO "$out/component.plist"
	i=$((i + 1))
done
echo "   $n_bundles bundle(s) pinned to their payload path (no relocation), payload applied regardless of the installed version"
pkgbuild --root "$root" --scripts "$scripts" --install-location / --component-plist "$out/component.plist" \
	--identifier "$pkg_id" --version "$build" "$comp" >/dev/null

cat > "$out/distribution.xml" <<DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>${app_exec}</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
    <volume-check>
        <allowed-os-versions><os-version min="${min_os}"/></allowed-os-versions>
    </volume-check>
    <choices-outline><line choice="default"/></choices-outline>
    <choice id="default" visible="false"><pkg-ref id="${pkg_id}"/></choice>
    <pkg-ref id="${pkg_id}" version="${build}">${app_exec}-component.pkg</pkg-ref>
</installer-gui-script>
DIST

echo "==> productbuild"
if [ -n "$installer_sign" ]; then
	productbuild --distribution "$out/distribution.xml" --package-path "$out" \
		--sign "$installer_sign" "$prod" >/dev/null
	echo "   signed by $(security find-identity -v | sed -n "s/.*$installer_sign \"\(.*\)\"/\1/p" | head -1)"
else
	productbuild --distribution "$out/distribution.xml" --package-path "$out" "$prod" >/dev/null
	echo "   (unsigned — correct for a $app_kind build; only a Developer ID app needs a signed archive)"
fi

# ---- 5. verify --------------------------------------------------------------------------------------------
echo "==> verifying"
exp="$out/.expanded"
rm -rf "$exp"
pkgutil --expand "$prod" "$exp"
[ -f "$exp/Distribution" ] || { echo "FAIL: no Distribution in the product archive"; exit 1; }
grep -q "os-version min=\"${min_os}\"" "$exp/Distribution" || { echo "FAIL: OS gate missing from Distribution"; exit 1; }
inner="$(ls -d "$exp"/*.pkg 2>/dev/null | head -1)"
[ -n "$inner" ] || { echo "FAIL: no component package inside"; exit 1; }
for s in preinstall postinstall; do
	f="$inner/Scripts/$s"
	[ -f "$f" ] || { echo "FAIL: $s is not in the package"; exit 1; }
	[ -x "$f" ] || { echo "FAIL: $s is not executable (the installer would skip it silently)"; exit 1; }
	# An unsubstituted __PLACEHOLDER__ ships a script that looks fine and does the wrong thing — check for it.
	! grep -q '__[A-Z_]*__' "$f" || { echo "FAIL: $s still contains an unsubstituted placeholder"; exit 1; }
	echo "  ok: $s present, executable, fully substituted"
done
echo "  ok: Distribution present with the macOS ${min_os} gate"
# ★ Asserted on the ARTIFACT. A <relocate> element in PackageInfo means PackageKit may install the app wherever
# it finds an older copy — which is how the first Developer ID install ended up writing into the build tree.
# Checking the component plist instead would only prove what was requested, not what was produced.
if grep -q "<relocate>" "$inner/PackageInfo" 2>/dev/null; then
	echo "FAIL: the component package is RELOCATABLE — PackageKit would install the app wherever it finds an older copy (a stray copy in ~/Downloads silently hijacks the install)"
	exit 1
fi
echo "  ok: bundles are pinned to their payload path (no relocation)"
# ★ Asserted on the ARTIFACT, like the relocation check above and for the same reason: the component plist
# proves what was requested, PackageInfo proves what was produced. A bundle listed under <bundle-version> is one
# PackageKit will refuse to overwrite with an older build — silently, after the preinstall has already
# authorised the rollback, reporting success. The rollback path is unusable while any bundle is listed here.
if python3 - "$inner/PackageInfo" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
listed = [b.get('id') for bv in root.findall('bundle-version') for b in bv.findall('bundle')]
print("\n".join(listed))
sys.exit(0 if listed else 1)
PY
then
	echo "FAIL: the component package is VERSION-CHECKED (bundles listed above). PackageKit would skip the payload"
	echo "      when a newer build is installed, so an authorised rollback would report success and change nothing."
	exit 1
fi
echo "  ok: no bundle is version-checked — an authorised rollback can actually replace the payload"
pkgutil --payload-files "$comp" | grep -qx "./Applications/${app_exec}.app" \
	&& echo "  ok: payload installs /Applications/${app_exec}.app" \
	|| { echo "FAIL: app missing from the payload"; exit 1; }
pkgutil --payload-files "$comp" | grep -qx "./Library/LaunchAgents/${app_id}.plist" \
	&& echo "  ok: payload installs the LaunchAgent" \
	|| { echo "FAIL: LaunchAgent missing from the payload"; exit 1; }
pkgutil --payload-files "$comp" | grep -qx "./Library/LaunchDaemons/${app_id}.updater.plist" \
	&& echo "  ok: payload installs the updater LaunchDaemon" \
	|| { echo "FAIL: updater LaunchDaemon missing from the payload"; exit 1; }
pkgutil --payload-files "$comp" | grep -qx "./Library/Application Support/Dsse/bin/dsse-updater" \
	&& echo "  ok: payload installs the updater binary" \
	|| { echo "FAIL: updater binary missing from the payload"; exit 1; }
# ★ The verifier and the uninstaller must be ON THE DEVICE. A check that only exists in this repository is not
# available on the machine that needs it, and an uninstall order that only exists in a runbook is an outage
# waiting for the first person who does it from memory.
for f in dsse-verify-install dsse-uninstall dsse-profileverify; do
	pkgutil --payload-files "$comp" | grep -qx "./Library/Application Support/Dsse/bin/$f" \
		&& echo "  ok: payload installs $f" \
		|| { echo "FAIL: $f missing from the payload"; exit 1; }
done
if [ -n "$installer_sign" ]; then
	pkgutil --check-signature "$prod" | head -3
fi

# ---- 6. notarize, staple, and then ASK GATEKEEPER ----------------------------------------------------------
#
# Only for a Developer ID build: a Development-signed lab package is installed by a person who is standing at
# the machine, and notarizing it would be a five-minute round trip to Apple for an artifact that will never
# leave this desk.
if [ "$app_kind" = "developer-id" ]; then
	notary_profile="${DSSE_NOTARY_PROFILE:-dsse-notary}"
	if [ "${DSSE_ALLOW_UNNOTARIZED:-0}" = "1" ]; then
		echo "==> DSSE_ALLOW_UNNOTARIZED=1 — skipping notarization"
	elif ! xcrun notarytool history --keychain-profile "$notary_profile" >/dev/null 2>&1; then
		# FATAL. An un-notarized Developer ID package is the most deceptive artifact this script can produce:
		# it installs perfectly on the Mac that built it, because Gatekeeper only enforces notarization on
		# files carrying the quarantine attribute — which the ones you build yourself do not have. It fails
		# for the first person who downloads it, and by then it looks like a distribution problem.
		echo "FAIL: no notarytool credentials in keychain profile '$notary_profile'."
		echo "  Store them once (interactive, needs an App Store Connect API key):"
		echo "    xcrun notarytool store-credentials $notary_profile \\"
		echo "      --key <AuthKey_XXXX.p8> --key-id <KEY_ID> --issuer <ISSUER_UUID>"
		echo "  Or DSSE_ALLOW_UNNOTARIZED=1 to build an archive that will NOT install on any other Mac."
		exit 1
	else
		echo "==> notarizing (this waits for Apple; typically 1-5 minutes)"
		# ★ THE EXIT CODE IS NOT THE ANSWER. `notarytool submit --wait` exits 0 when the submission COMPLETES,
		# including when it completes with status Invalid — the run that found this printed
		# "status: Invalid" and returned success, and the build carried on to stapling as though notarized.
		# Exactly the mistake this file's header warns about, made in the file that warns about it: an exit
		# code answers "did the tool run", never "did the thing happen".
		sub="$out/.notarize.json"
		xcrun notarytool submit "$prod" --keychain-profile "$notary_profile" --wait \
			--output-format json > "$sub" 2>&1 || true
		notary_status="$(sed -n 's/.*"status":"\([^"]*\)".*/\1/p' "$sub" | tail -1)"
		notary_id="$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$sub" | tail -1)"
		echo "   submission $notary_id -> ${notary_status:-unknown}"
		if [ "$notary_status" != "Accepted" ]; then
			echo "FAIL: notarization returned '${notary_status:-unknown}'. Apple's reasons:"
			# Printed HERE rather than left as a command to run: the log names the exact file and the exact
			# defect, and a reader who has to go and fetch it is a reader who guesses instead.
			xcrun notarytool log "$notary_id" --keychain-profile "$notary_profile" 2>&1 |
				sed -n 's/^ *"\(message\|path\)": /  /p' | head -20
			exit 1
		fi
		# ★ STAPLING IS A SEPARATE FACT FROM NOTARIZING. Without it the ticket is only online, and the machine
		# that most needs to install without asking Apple is the one that cannot reach Apple.
		echo "==> stapling"
		xcrun stapler staple "$prod" || { echo "FAIL: could not staple the ticket to $prod"; exit 1; }
		xcrun stapler validate "$prod" || { echo "FAIL: stapler reports no valid ticket on $prod"; exit 1; }
		echo "  ok: a notarization ticket is stapled to the package itself"
	fi

	# The last word belongs to the component that will actually refuse the install. Both assessments are run
	# because they answer different questions: --type install is the installer's gate, --type exec is the one
	# the app faces at first launch, and a package can pass the first while carrying an app that fails the
	# second — which presents to a customer as "it installed and then nothing happened".
	echo "==> Gatekeeper's own assessment"
	pkg_verdict="$(spctl -a -vv --type install "$prod" 2>&1 || true)"
	app_verdict="$(spctl -a -vv --type exec "$src_app" 2>&1 || true)"
	printf '  package: %s\n' "$(printf '%s' "$pkg_verdict" | tr '\n' ' ')"
	printf '  app:     %s\n' "$(printf '%s' "$app_verdict" | tr '\n' ' ')"
	if [ "${DSSE_ALLOW_UNNOTARIZED:-0}" != "1" ]; then
		case "$pkg_verdict" in *accepted*) : ;; *) echo "FAIL: Gatekeeper rejects the package"; exit 1 ;; esac
		case "$app_verdict" in *accepted*) : ;; *) echo "FAIL: Gatekeeper rejects the app inside it"; exit 1 ;; esac
		echo "  ok: Gatekeeper accepts both — this package installs on a Mac that has never seen it"
	fi
fi

echo "==> built: $prod"
