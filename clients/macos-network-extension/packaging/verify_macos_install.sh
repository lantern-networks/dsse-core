#!/bin/sh
# Did the install actually produce a steering device? Run after installing the .pkg.
#
#   sh deploy/reference/verify_macos_install.sh [expected-interception-CA-substring]
#
# ★ WHY THIS EXISTS (2026-08-10). The Developer ID package installed cleanly, the system extension reached
# `activated enabled`, the transparent proxy configuration was created, and the tunnel reported `connected`.
# Every indicator an installer can check was green. The device had NO WORKING HTTPS AT ALL.
#
# That is this tree's recurring shape arriving at the last place it had not been closed: reported as success,
# correct in the record, wrong only in whether the thing actually works. An installer that stops at "the files
# are in place" ships that failure to every machine it touches — and on a security agent the failure mode is
# either no connectivity or, worse, connectivity with no inspection.
#
# So the last check has to be the one the ENDPOINT performs: real TLS to a real host, and look at who signed it.
#
# Exit 0 only if the device is genuinely steering. Every check prints what it observed, because a verifier that
# only says PASS/FAIL is a verifier nobody can debug.
set -eu

# ★★★ MEASURED AGAINST THE ROOT THE ORGANIZATION ANNOUNCED, NOT AGAINST A NAME (2026-08-30). This defaulted to
# the substring "Lantern DSSE" and compared it against the ISSUER of the presented leaf. Every organization
# with its own interception authority is issued under its OWN name — "CN=Kaede Trading Interception Issuing CA
# — dsse-edge-fleet" — so this verifier reported "NOT inspected" against a certificate the organization's own
# CA had signed seconds earlier, on a device that was inspecting perfectly. A verifier that fails on the
# product working correctly is worse than none: the next person fixes the device.
#
# The installed profile already carries the one fact that settles it, deployment.interception_root_pem. The
# question asked below is whether the chain the server PRESENTS leads to that root — which needs no name and
# no trust store, so it also cannot be fooled by a root this machine happens to trust.
#
# A substring may still be given (argument or DSSE_EXPECT_INTERCEPTION_CA) for a device with no profile in
# place; it is the fallback, no longer the default.
profile_path="${DSSE_INSTALL_PROFILE:-/Library/Application Support/Dsse/install_profile.json}"
announced_root=""
if [ -f "$profile_path" ]; then
	announced_root="$(mktemp -t dsse-announced-root)"
	/usr/bin/python3 - "$profile_path" "$announced_root" <<'ANNOUNCED' || announced_root=""
import base64, json, pathlib, sys
env = json.loads(pathlib.Path(sys.argv[1]).read_text())
body = json.loads(base64.b64decode(env["payload_b64"]))
pem = ((body.get("deployment") or {}).get("interception_root_pem") or "").strip()
if not pem:
    sys.exit(1)
pathlib.Path(sys.argv[2]).write_text(pem + "\n")
ANNOUNCED
fi
[ -n "$announced_root" ] && [ -s "$announced_root" ] || announced_root=""
root_subject=""
[ -n "$announced_root" ] && root_subject="$(openssl x509 -in "$announced_root" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
expect_ca="${1:-${DSSE_EXPECT_INTERCEPTION_CA:-Lantern DSSE}}"
fail=0
ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '       %s\n' "$1"; }

app_id="${DSSE_APP_BUNDLE_ID:-jp.co.lantern-networks.dsse.agent}"
app_exec="${DSSE_APP_EXEC:-LanternDsseAgent}"
sx_id="${app_id}.networkextension"
app="/Applications/${app_exec}.app"

echo "== 1. installed files =="
[ -d "$app" ] && ok "$app" || bad "$app is missing"
# ★ Relocation check. PackageKit installs into an existing copy of the same bundle id if it finds one, so a
# stray copy in ~/Downloads or a build tree silently takes the install. It happened here on the first attempt.
# Reported, not failed. The package is built non-relocatable, so a stray copy can no longer capture an
# install — but it is still worth naming, because that mitigation lives in the BUILD and someone hand-rolling a
# package would lose it. On a developer machine these are usually build outputs; on a user's Mac they are not.
others="$(mdfind "kMDItemCFBundleIdentifier == '$app_id'" 2>/dev/null | grep -v "^/Applications/" || true)"
if [ -n "$others" ]; then
	n_others="$(printf '%s\n' "$others" | grep -c .)"
	note "$n_others other copies of $app_id exist outside /Applications (harmless with a non-relocatable package):"
	printf '%s\n' "$others" | head -3 | sed 's/^/         /'
	[ "$n_others" -gt 3 ] && note "         … and $((n_others - 3)) more"
fi
for f in "/Library/LaunchAgents/${app_id}.plist" "/Library/LaunchDaemons/${app_id}.updater.plist"; do
	[ -e "$f" ] && ok "$(basename "$f")" || bad "$f is missing"
done

# ★ AND WHAT IT SAYS, NOT ONLY THAT IT EXISTS (2026-08-14, from the Windows box — handoff). Over there the
# service existed, was running, and reported healthy while running the ONE-SHOT VERIFICATION branch: the MSI's
# arguments omitted --permanent, so the agent self-terminated at ~2 minutes and nothing recreated it. Existence
# was never the question; the arguments were, and nothing looked at them for weeks.
#
# The macOS shape is the same by construction — the resident mode is a NON-DEFAULT flag (--loop), so the daemon
# is only resident if the installer got it right — and this Mac is correct today. That is exactly why it is
# worth asserting: a future packaging change that drops the flag would leave an updater that runs one pass at
# boot and looks entirely healthy.
d="/Library/LaunchDaemons/${app_id}.updater.plist"
if [ -e "$d" ]; then
	args="$(plutil -extract ProgramArguments json -o - "$d" 2>/dev/null || true)"
	# `raw` first, `json` second: plutil cannot emit a top-level boolean as JSON ("Invalid object in plist for
	# JSON format"), so asking for json alone reported KeepAlive as ABSENT on a plist that plainly has
	# <key>KeepAlive</key><true/>. Caught by running this check against a correct machine — a verifier's first
	# duty is not to invent failures. The json form is still needed for the dictionary spelling
	# ({"SuccessfulExit": false}), which `raw` cannot render.
	keep="$(plutil -extract KeepAlive raw -o - "$d" 2>/dev/null || plutil -extract KeepAlive json -o - "$d" 2>/dev/null || true)"
	case "$args" in
	*'"--loop"'*) ok "the updater daemon runs resident (--loop)" ;;
	*) bad "the updater daemon does NOT pass --loop — it will make one pass and exit, and look healthy doing it (args: ${args:-unreadable})" ;;
	esac
	case "$keep" in
	true | *'"SuccessfulExit":false'*) ok "launchd restarts the updater (KeepAlive)" ;;
	*) bad "the updater daemon has no KeepAlive — a clean exit ends it until the next boot, and a clean exit is exactly what a bug looks like from launchd (KeepAlive: ${keep:-absent})" ;;
	esac
fi
# ★ Under a root-only directory, so a non-root run cannot stat it. Reporting "missing" there would be a
# verifier inventing a failure — the exact thing this script exists to stop doing.
updater="/Library/Application Support/Dsse/bin/dsse-updater"
if [ "$(id -u)" = "0" ]; then
	[ -x "$updater" ] && ok "dsse-updater" || bad "$updater is missing or not executable"
else
	note "dsse-updater not checked (its directory is root-only; re-run with sudo to include it)"
fi

echo "== 2. code identity =="
if a="$(codesign -dvv "$app" 2>&1 | sed -n 's/^Authority=//p' | head -1)"; then
	case "$a" in
	"Developer ID Application"*) ok "signed: $a" ;;
	"Apple Development"*) note "development-signed: $a (fine for a lab machine, NOT distributable)" ;;
	*) bad "unexpected signing authority: $a" ;;
	esac
fi

echo "== 3. system extension =="
line="$(systemextensionsctl list 2>/dev/null | grep -F "$sx_id" | grep -F "[activated enabled]" | head -1 || true)"
if [ -n "$line" ]; then
	ok "$sx_id is activated enabled"
else
	pending="$(systemextensionsctl list 2>/dev/null | grep -F "$sx_id" | grep -F "waiting for user" | head -1 || true)"
	if [ -n "$pending" ]; then
		bad "$sx_id is WAITING FOR USER — approve it in System Settings › General › Login Items & Extensions › Network Extensions"
	else
		bad "$sx_id is not activated"
	fi
fi
# ★ THE NAME COMES FROM THE INSTALLED BUNDLE, not from a default this script invents.
#
# It used to default to DsseAppProxyProvider while the BUILDER defaulted to the retired
# DsseAppProxyProvider. Nothing compared the two, so a build that omitted DSSE_SYSEXT_EXEC shipped the
# old name and this check reported "the provider process is NOT running" on a machine that was steering and
# inspecting. A verifier holding its own opinion about what it is verifying will eventually disagree with it.
sx_exec="$(basename "$(ls "$app/Contents/Library/SystemExtensions/"*.systemextension/Contents/MacOS/* 2>/dev/null | head -1)" 2>/dev/null)"
if [ -z "$sx_exec" ]; then
	bad "cannot read the provider executable name out of $app — the bundle is not shaped as expected"
elif pgrep -f "$sx_exec" >/dev/null 2>&1; then
	ok "the provider process is running ($sx_exec)"
else
	bad "the provider process ($sx_exec) is NOT running"
fi

echo "== 4. the device's own record of the install =="
# ★ This slot used to check that the agent config mentions this bundle id, on the theory that the agent must
# self-exclude. It fired on a HEALTHY machine — the self-exclusion list has never contained the agent's own
# identifier, on either build, and steering works. A note that every good install prints is a note nobody
# reads, which is the failure mode this whole script exists to avoid. Removed rather than softened.
#
# What is worth checking here is the thing the installer WRITES and nothing else reads: its own account of what
# is done and what is still pending.
cfg="/Library/Application Support/Dsse/agent_config.json"
state="/Library/Application Support/Dsse/install_state.json"
if [ "$(id -u)" != "0" ]; then
	note "skipped (root-only files; re-run with sudo)"
else
	if [ -f "$cfg" ] && python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$cfg" >/dev/null 2>&1; then
		ok "agent config is present and parses"
	else
		bad "$cfg is missing or not valid JSON — the provider has nothing to configure itself from"
	fi
	if [ -f "$state" ]; then
		pending="$(python3 -c "import json,sys;print(','.join(json.load(open(sys.argv[1])).get('pending') or []) or 'none')" "$state" 2>/dev/null || echo "unreadable")"
		case "$pending" in
		none) ok "install_state.json reports nothing pending" ;;
		unreadable) bad "$state is not readable JSON" ;;
		# ★★★ AND THE APPROVAL IT REPORTS PENDING IS ASKED OF THE OS, NOT OF THIS FILE (2026-09-05, measured on
		# a Mac that was steering and inspecting perfectly while this line failed the install).
		#
		# install_state.json is written by the postinstall, which asks the OS DURING the install — before the
		# extension can possibly have activated. On a Mac where approval is automatic, or where this bundle was
		# approved once before, it activates seconds later and nothing rewrites the file. The photograph is
		# taken at the one moment it cannot be right, and section 3 above has already asked the OS itself.
		system_extension_user_approval)
			if systemextensionsctl list 2>/dev/null | grep -q "activated enabled"; then
				ok "install_state.json still says the extension is awaiting approval; the OS says it is "\
"activated enabled, which is the answer that counts — nothing rewrites this file after the approval"
			else
				bad "install_state.json reports pending: $pending, and the OS agrees the extension is not "\
"activated. Approve it in System Settings > General > Login Items & Extensions > Network Extensions"
			fi ;;
		*) bad "install_state.json still reports pending: $pending" ;;
		esac
	else
		note "no install_state.json — written by packages built after 2026-08-10; older installs do not have one"
	fi
fi

echo "== 4b. ★ can this device ever be updated? =="
# The updater daemon verifies an update manifest against pinned Ed25519 keys read from the agent config. With
# none it runs forever, refuses correctly on every pass, and can never install anything — into a root-only log
# nobody reads. That state is invisible from outside, and it is the state that shipped, so the device is asked
# directly rather than inferred from the files being present.
if [ "$(id -u)" != "0" ]; then
	note "skipped (the updater's state is root-only; re-run with sudo)"
elif [ -x "$updater" ]; then
	st="$("$updater" --status 2>&1 || true)"
	src="$(printf '%s\n' "$st" | sed -n 's/^  update key from *: //p')"
	if printf '%s' "$st" | grep -q "can NEVER update"; then
		bad "this Mac can NEVER be updated — no update-signing key is pinned. ${src:-(no key source reported)}"
	elif printf '%s' "$st" | grep -q "could NOT be read"; then
		bad "the updater cannot read its signing keys: ${src:-unknown}"
	else
		ok "the updater is pinned and can accept an update (${src:-source not reported})"
	fi
else
	note "dsse-updater is not installed, so this Mac has no way to receive an update"
fi

echo "== 5. the transparent proxy is configured AND enabled =="
if scutil --nc list 2>/dev/null | grep -qi "dsse\|lantern"; then
	ok "a DSSE transparent proxy configuration is present"
else
	note "scutil does not list it by name (transparent proxies are often not shown) — relying on the traffic test"
fi

echo "== 6. ★ the endpoint test — is traffic actually steered and inspected? =="
# This is the check the others exist to lead up to. Everything above can pass on a device with no connectivity.
probe() { # host, expectation: intercepted|direct
	host="$1"
	chain="$(mktemp -t dsse-presented-chain)"
	echo | openssl s_client -connect "$1:443" -servername "$1" -showcerts >"$chain" 2>/dev/null || true
	iss="$(openssl x509 -noout -issuer <"$chain" 2>/dev/null | sed 's/^issuer=//')"
	if [ -z "$iss" ]; then
		rm -f "$chain"
		bad "$1: NO TLS AT ALL — the device cannot reach it. Steering is capturing the flow and dropping it."
		return
	fi
	# Does the presented chain lead to the root the deployment announced? Read from the certificates the
	# server sent — one of them names the announced root as its issuer — so no trust store is consulted. On
	# macOS every TLS client consults the keychain, where the interception root IS trusted, which is why a
	# `--cacert` or `openssl verify` answer here would say yes to a bundle that does not contain the root.
	if [ -n "$root_subject" ]; then
		if grep -q "^ *i:$(printf '%s' "$root_subject" | sed 's/[][\.*^$/]/\\&/g')\$" "$chain"; then
			leads_to_root=yes
		else
			leads_to_root=no
		fi
	else
		# No profile to measure against: fall back to the substring, and say so, because a name match is a
		# weaker claim than a chain and the reader must not read one as the other.
		case "$iss" in *"$expect_ca"*) leads_to_root=yes ;; *) leads_to_root=no ;; esac
	fi
	# ★★★ AND WHETHER THIS DEVICE ACTUALLY ACCEPTS IT, WHICH IS THE QUESTION A BROWSER ASKS (2026-09-04,
	# measured on a real Mac). Everything above establishes that the deployment is re-signing traffic. It says
	# nothing about whether this machine will LOAD a page — and on the day this was written the machine would
	# not: the announced authority had been installed with `-r trustRoot`, which is the verb for a self-signed
	# root, while what was announced was an intermediate. macOS kept looking for the issuer above it and
	# refused every chain. `security find-certificate` found it, `openssl s_client` printed its name, this
	# check said "is inspected", and Chrome showed a certificate error on every page.
	#
	# So the leaf is now put to the system trust store, with the SSL policy, exactly as a browser would.
	#
	# ★★★ WITH THE INTERMEDIATES THE SERVER PRESENTED, WHICH THIS ASKED WITHOUT (2026-09-05, measured on a Mac
	# whose browser was loading pages perfectly while this said it was not). `security verify-cert -c <leaf>`
	# is given ONE certificate, and macOS can only complete the chain from what is in a keychain — the
	# deployment's issuing tier is not, and never will be: it is minted per Edge and changes. So the check
	# answered "not trusted" for every inspected host on a device where every browser worked, and printed a
	# fix for a fault that was not there.
	#
	# A browser is handed the whole chain in the handshake. This hands it the same thing: every certificate
	# the server presented, leaf first, which is what -c repeated means.
	#
	# ★★★ AND IT IS ASKED BY LOADING THE PAGE, NOT BY `security verify-cert` (2026-09-05, measured on a Mac
	# that was steering and inspecting perfectly while this said it was not).
	#
	# `security verify-cert -c <leaf> -p ssl -s <host>` refused a chain that the system itself accepts: the
	# deployment's issuing tier is presented in the handshake and is in no keychain, so the tool could not
	# complete the chain, and adding the presented certificates with more -c did not settle it either. It
	# printed CSSMERR_TP_NOT_TRUSTED for a device whose every client loaded the page, and this check turned
	# that into "every browser on this Mac shows a certificate error" — a sentence about the tool.
	#
	# nscurl is NSURLSession, which is the stack Safari and every system client actually use, so this now asks
	# the question the way the thing being asked about asks it. It exits 0 either way and says what happened
	# on stdout, so the answer is read from the text rather than from the status.
	trusted=unknown
	rm -f "$chain"
	if command -v nscurl >/dev/null 2>&1; then
		if nscurl -o /dev/null "https://$host/" 2>&1 | grep -q "Load failed with error"; then trusted=no; else trusted=yes; fi
	fi
	case "$2:$leads_to_root:$trusted" in
	intercepted:yes:no)
		bad "$1 is inspected ($iss) and this device DOES NOT TRUST it — every browser on this Mac shows a "\
"certificate error: NSURLSession, the stack Safari and every system client use, refused to load it. The "\
"announced authority is installed but not trusted for TLS. Read the certificate before choosing the verb: a "\
"self-signed root (subject == issuer) is installed with 'security add-trusted-cert -d -r trustRoot -p ssl'; "\
"an intermediate needs '-r trustAsRoot'. Check what was written with 'security dump-trust-settings -d'" ;;
	esac
	case "$2:$leads_to_root:$trusted" in
	intercepted:yes:yes) ok "$1 is inspected ($iss), and this device trusts it — a browser loads it" ;;
	intercepted:yes:unknown)
		note "$1 is inspected ($iss); nscurl is not on this Mac, so whether a browser loads it was NOT "\
"established here — this is neither a pass nor a failure" ;;
	intercepted:no:*)
		if [ -n "$root_subject" ]; then
			bad "$1 is NOT inspected — issuer is $iss; no certificate in the presented chain is signed by the announced root ($root_subject)"
		else
			bad "$1 is NOT inspected — issuer is $iss, expected one containing '$expect_ca' (no install profile to measure against)"
		fi ;;
	direct:yes:*) bad "$1 is being inspected but must not be ($iss)" ;;
	direct:no:*)  ok "$1 is passed through ($iss)" ;;
	esac
}
if [ -n "$root_subject" ]; then
	note "interception is measured against the root this deployment announced: $root_subject"
else
	note "no install profile here — falling back to matching the issuer name against '$expect_ca'"
fi
probe www.google.com intercepted
# A certificate-pinned host that MUST be passed through. If this one is inspected, `stapler`, the App Store and
# software update break in ways that never mention a proxy.
probe api.apple-cloudkit.com direct

# ★★★ 6b. A VIRTUAL MACHINE ON THIS DEVICE HAS ITS OWN NETWORK STACK (2026-09-01, measured on both platforms
# in one afternoon). The agent promises to steer ALL outbound traffic, and a guest is the part that can fall
# outside it — on Windows it does: a WSL2 distro imported by a STANDARD user, with no elevation, egressed
# straight to the public internet while the agent reported steering, and nothing on the box said so.
#
# macOS held: a VM here, holding its own address on a shared vmnet, still egressed through the deployment. But
# that was ONE measurement on ONE machine, and a fact nobody re-measures is a fact about the day it was taken.
# So it is asked here, on every device, in the only way that answers it — from inside the guest.
#
# ★ NOT A FAILURE WHEN THERE IS NO VM. Most devices run none, and "this device has no virtual machine" is a
# different answer from "its virtual machine escapes" — reporting them the same way is how a check stops being
# read. Only an ESCAPE fails.
echo
echo "== 6b. ★ virtual machines on this device — do they leave through the deployment? =="
# ★★★ VERIFIED, NOT COMPARED (2026-09-01, and the second time in one screen). The first version matched the
# guest's issuer against a name; the second matched the announced root's subject against the guest's chain
# text. BOTH reported a correctly steered VM as an escape, because the guest's OpenSSL renders a subject as
# "CN = X" and this machine's renders it "CN=X". Two spaces, and the check accuses the device of the worst
# thing it knows how to say.
#
# The root this deployment announced is on disk. So the question is asked the only way that cannot be spelled
# wrong: does the chain the guest was SHOWN build to that root. -CAfile names the one root and nothing else,
# so no trust store is consulted and a keychain that trusts it cannot answer for the guest.
vm_probed=no
vm_root="/Library/Application Support/Dsse/interception-root.pem"
if command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1; then
	vm_probed=yes
	vm_chain="$(mktemp -t dsse-vm-chain)"
	colima ssh -- sh -c 'echo | openssl s_client -connect example.com:443 -servername example.com -showcerts 2>/dev/null' \
		>"$vm_chain" 2>/dev/null || true
	vm_iss="$(openssl x509 -noout -issuer <"$vm_chain" 2>/dev/null | sed 's/^issuer=//')"
	if [ -z "$vm_iss" ]; then
		note "the virtual machine could not be asked (no TLS answer) — this check proves nothing here"
	elif [ ! -f "$vm_root" ]; then
		note "this device holds no announced interception root, so the guest's chain cannot be measured"
	elif openssl verify -CAfile "$vm_root" -untrusted "$vm_chain" "$vm_chain" >/dev/null 2>&1; then
		ok "the virtual machine's traffic is carried by this deployment (chain builds to its announced root)"
	else
		bad "★ the virtual machine on this device reaches the internet WITHOUT this deployment (issuer: $vm_iss) — its traffic is not steered, not inspected and not recorded, and no administrator rights are needed to start one"
	fi
	rm -f "$vm_chain"
fi
[ "$vm_probed" = no ] && note "no virtual machine runtime found here — nothing to ask (this is not a pass)"

echo "== 7. plain reachability =="
code="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' https://www.apple.com 2>/dev/null || echo 000)"
[ "$code" = "200" ] && ok "https://www.apple.com -> $code" || bad "https://www.apple.com -> $code (the device cannot browse)"

echo
if [ "$fail" -eq 0 ]; then
	echo "verify_macos_install: PASS — the device is installed, approved, and STEERING."
	exit 0
fi
echo "verify_macos_install: $fail check(s) FAILED — the install is NOT complete."
echo "A green install and a green extension prove the files are in place; they do not prove the device works."
exit 1
