#!/bin/sh
# Generate the MDM configuration profile that pre-approves this agent's system extension.
#
#   sh deploy/reference/build_macos_mdm_profile.sh [/Applications/LanternDsseAgent.app] [out.mobileconfig]
#
# ★ WHY (2026-08-10). Installing the agent on this Mac required a person to find
# System Settings > General > Login Items & Extensions > Network Extensions and flip a switch — after first
# learning that the notification's OK button dismisses rather than approves. That is the single largest piece
# of human work in the install, it cannot be removed for an unmanaged Mac, and for a MANAGED one it disappears
# entirely: an MDM-delivered com.apple.system-extension-policy payload naming the team and the extension
# pre-approves it, and the extension activates with no click at all. This is the macOS counterpart of the
# Windows MSI's unattended install, and it is the thing the Apple Developer ORGANIZATION conversion unlocked
# (docs/apple_developer_organization_unlocks.ja.md-2).
#
# ★★ AND THE VALUES ARE READ FROM THE BUILT APP, NEVER TYPED. A profile that names a team or an extension id
# the app does not actually have is the worst outcome available here: it installs cleanly, reports success, and
# pre-approves NOTHING — so the extension silently falls back to asking a user who is not there, and a fleet
# rollout stalls with every device reporting a healthy profile. Today already proved that this product's team
# id and extension id both change (the rebrand moved one; a re-sign can move the other), so a hand-written
# profile is a copy of the truth that will drift. This reads codesign's answer about the actual bundle.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
app="${1:-/Applications/${DSSE_APP_EXEC:-LanternDsseAgent}.app}"
out="${2:-$here/../../var/dsse-system-extension-policy.mobileconfig}"

[ -d "$app" ] || { echo "build_macos_mdm_profile: no app bundle at $app"; exit 1; }

sx="$(ls -d "$app/Contents/Library/SystemExtensions/"*.systemextension 2>/dev/null | head -1)"
[ -n "$sx" ] && [ -d "$sx" ] || { echo "build_macos_mdm_profile: $app embeds no .systemextension"; exit 1; }

read_cs() { codesign -dv "$1" 2>&1 | sed -n "s/^$2=//p" | head -1; }
app_team="$(read_cs "$app" TeamIdentifier)"
sx_team="$(read_cs "$sx" TeamIdentifier)"
sx_id="$(read_cs "$sx" Identifier)"
app_id="$(read_cs "$app" Identifier)"

for v in "$app_team:app team" "$sx_team:extension team" "$sx_id:extension identifier" "$app_id:app identifier"; do
	[ -n "${v%%:*}" ] || { echo "build_macos_mdm_profile: could not read the ${v#*:} from the signature"; exit 1; }
done

# ★ The pair must agree, and this is not a formality. The extension is approved by (team, identifier); if the
# app and its embedded extension were signed by different teams the profile would pre-approve something that is
# not what runs, and the failure would look like "the profile did nothing".
[ "$app_team" = "$sx_team" ] || {
	echo "build_macos_mdm_profile: the app is team $app_team but its extension is team $sx_team — refusing to"
	echo "  emit a profile that pre-approves a team the running extension does not belong to."
	exit 1
}
# The runtime invariant the rest of the tree relies on: the extension id is ALWAYS the app id + suffix, because
# the agent derives its activation target that way. A profile built from a bundle that violates it would
# pre-approve an extension the agent will never ask for.
[ "$sx_id" = "${app_id}.networkextension" ] || {
	echo "build_macos_mdm_profile: extension id '$sx_id' is not '${app_id}.networkextension' — the agent derives"
	echo "  its activation target from the app id, so this profile would approve something it never activates."
	exit 1
}

uuid_payload="$(uuidgen)"
uuid_profile="$(uuidgen)"

mkdir -p "$(dirname "$out")"
cat > "$out" <<PROFILE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadVersion</key><integer>1</integer>
	<key>PayloadIdentifier</key><string>${app_id}.system-extension-policy</string>
	<key>PayloadUUID</key><string>${uuid_profile}</string>
	<key>PayloadDisplayName</key><string>Lantern DSSE — approve the network extension</string>
	<key>PayloadDescription</key><string>Pre-approves the Lantern DSSE network extension so it activates without asking the person using the Mac.</string>
	<key>PayloadOrganization</key><string>Lantern Networks, Inc.</string>
	<key>PayloadScope</key><string>System</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key><string>com.apple.system-extension-policy</string>
			<key>PayloadVersion</key><integer>1</integer>
			<key>PayloadIdentifier</key><string>${app_id}.system-extension-policy.payload</string>
			<key>PayloadUUID</key><string>${uuid_payload}</string>
			<key>PayloadDisplayName</key><string>System Extension policy</string>
			<key>PayloadOrganization</key><string>Lantern Networks, Inc.</string>
			<!-- Named EXTENSIONS, not "any extension from this team". A team-wide allowance would pre-approve
			     anything this signing identity ever ships, including a build nobody reviewed. -->
			<key>AllowedSystemExtensions</key>
			<dict>
				<key>${sx_team}</key>
				<array>
					<string>${sx_id}</string>
				</array>
			</dict>
			<!-- Deliberately NOT set: AllowUserOverrides. Letting a user turn the extension off on a managed
			     device makes the security control optional for exactly the person it constrains. -->
		</dict>
	</array>
</dict>
</plist>
PROFILE

# Structural validation. A .mobileconfig that does not parse is rejected by MDM with a message about the
# profile, not about what is wrong inside it.
plutil -lint "$out" >/dev/null || { echo "build_macos_mdm_profile: the generated profile is not a valid plist"; exit 1; }

# ★ Read the values BACK OUT of the file and compare them to the bundle. Generating from the app and then
# checking the generated file against the app is not redundant: it is the difference between "we intended to
# write the right team" and "the right team is in the file".
got_team="$(plutil -extract PayloadContent.0.AllowedSystemExtensions json -o - "$out" | sed -n 's/.*"\([A-Z0-9]\{10\}\)".*/\1/p' | head -1)"
got_ext="$(plutil -extract PayloadContent.0.AllowedSystemExtensions json -o - "$out" | sed -n 's/.*\["\([^"]*\)"\].*/\1/p' | head -1)"
[ "$got_team" = "$sx_team" ] || { echo "build_macos_mdm_profile: team in the profile ($got_team) != the bundle ($sx_team)"; exit 1; }
[ "$got_ext" = "$sx_id" ] || { echo "build_macos_mdm_profile: extension in the profile ($got_ext) != the bundle ($sx_id)"; exit 1; }

echo "==> wrote $out"
echo "    team      $sx_team"
echo "    extension $sx_id"
echo "    verified against $app"
echo ""
echo "    Deliver it through MDM. Installing it BY HAND still requires the same person to approve the profile,"
echo "    which defeats the purpose — the point is that a managed Mac gets it before the agent ever asks."
