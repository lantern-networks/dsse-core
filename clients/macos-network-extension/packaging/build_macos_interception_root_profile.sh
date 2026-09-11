#!/bin/sh
# Generate the MDM configuration profile that puts an ORGANIZATION'S interception roots into a Mac's trust
# store — the one step of this install that had no channel at all.
#
#   sh clients/macos-network-extension/packaging/build_macos_interception_root_profile.sh \
#        --edge-admin https://127.0.0.1:9443 --tenant <tenant-id> --token <admin token> [--out FILE] [--ca FILE]
#
# ★★★ WHY (2026-08-27, found by asking whether the Mac side of this walk was the standard install). Three of
# the four steps had a supported lane — the configuration is a documented precondition, the package is signed
# and notarised, the system extension is pre-approved by a com.apple.system-extension-policy payload. The
# fourth was
#
#	sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <root>
#
# typed by a person, on one Mac. Nothing in this repository produced a profile carrying that certificate, and
# there is no other way in: the agent deliberately only LOOKS at the trust store (DsseInterceptionRootTrust) —
# an agent that could write to the System keychain would itself be a way to make this machine trust anything.
# So on a fleet, the step that decides whether every HTTPS request works was a manual one.
#
# ★★ THE CERTIFICATES ARE READ FROM THE NODE THAT SIGNS, NEVER FROM A FILE SOMEBODY KEPT. An operator holding
# the root as a file cannot tell whether it is the one an Edge currently mints under: the same organization's
# authority can have been replaced, and a profile built from last month's copy installs cleanly, reports
# success, and trusts a root nothing signs with. The Edge's admin surface answers what it actually uses.
#
# ★★★ AND IT CARRIES EVERY ROOT THE DEPLOYMENT ANNOUNCES, not just the one in force. Replacing an
# organization's authority is announce, MEASURE, switch, withdraw: during the overlap a device may legitimately
# be verifying against the outgoing root, and before the switch it has to already hold the incoming one or the
# adoption measurement never leaves zero. A profile carrying one root turns every rotation into a flag day.
set -eu

edge=""; tenant=""; token=""; out=""; ca=""
while [ $# -gt 0 ]; do
	case "$1" in
		--edge-admin) edge="$2"; shift 2 ;;
		--tenant) tenant="$2"; shift 2 ;;
		--token) token="$2"; shift 2 ;;
		--out) out="$2"; shift 2 ;;
		--ca) ca="$2"; shift 2 ;;
		*) echo "build_macos_interception_root_profile: unknown argument $1" >&2; exit 1 ;;
	esac
done
[ -n "$edge" ] || { echo "build_macos_interception_root_profile: --edge-admin is required — the roots are read from the node that signs" >&2; exit 1; }
[ -n "$tenant" ] || { echo "build_macos_interception_root_profile: --tenant is required — an interception root belongs to ONE organization, and a device is in one of them" >&2; exit 1; }
[ -n "$token" ] || { echo "build_macos_interception_root_profile: --token is required" >&2; exit 1; }

here="$(cd "$(dirname "$0")" && pwd)"
out="${out:-$here/../../var/dsse-interception-roots-$tenant.mobileconfig}"
mkdir -p "$(dirname "$out")"

# ★ THE ADMIN SURFACE OF AN EDGE IS ITS OWN, NOT THE REGION DOORWAY'S: this asks the node, because the answer
# is about that node — which root IT mints under. Give --ca to verify it properly; without one this falls back
# to an unverified connection and says so, because a silent -k is how an operator ends up building a profile
# from whatever answered.
if [ -n "$ca" ]; then
	answer="$(curl -sS --max-time 30 --cacert "$ca" -H "Authorization: Bearer $token" \
		-H "X-Operate-Tenant: $tenant" "${edge%/}/admin/interception-roots")" || {
		echo "build_macos_interception_root_profile: $edge could not be asked" >&2; exit 1; }
else
	echo "build_macos_interception_root_profile: NOTE — no --ca was given, so this Edge's certificate is not" >&2
	echo "  verified. Fine on a loopback admin port; on anything else, pass the deployment's anchor." >&2
	answer="$(curl -sSk --max-time 30 -H "Authorization: Bearer $token" \
		-H "X-Operate-Tenant: $tenant" "${edge%/}/admin/interception-roots")" || {
		echo "build_macos_interception_root_profile: $edge could not be asked" >&2; exit 1; }
fi

# ★ THE ANSWER GOES THROUGH A FILE, NOT A PIPE. The reader below arrives on stdin as a heredoc, so piping the
# Edge's answer into the same stdin silently hands python an empty document — which reported "the Edge did not
# answer with JSON" about a route that had just answered 200.
answer_file="$(mktemp)"
trap 'rm -f "$answer_file"' EXIT
printf '%s' "$answer" > "$answer_file"
python3 - "$tenant" "$out" "$answer_file" <<'PY'
import base64, hashlib, json, plistlib, sys, uuid

tenant, out, answer_file = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(answer_file).read()
try:
    doc = json.loads(raw)
except Exception:
    sys.exit("build_macos_interception_root_profile: the Edge did not answer with JSON:\n  " + raw[:400])

rows = [r for r in (doc.get("per_tenant_issuers") or []) if r.get("tenant", "").lower() == tenant.lower()]
scope = (doc.get("signing_scope") or {})
shared = ""

# ★★★ DISTRIBUTE THE ROOT THAT ACTUALLY SIGNS, WHICH IS NOT ALWAYS THE ORGANIZATION'S (2026-09-04, found by
# walking a Mac onto a deployment built from the published tree). This read per_tenant_issuers alone and
# refused when it was empty — "a profile built now would install a root that nothing mints under" — on a
# deployment where the very traffic on the wire was being re-signed by a root this same answer was handing
# over, one field along, as default_root_pem.
#
# A deployment inspects under its own root until an organization brings one of its own; that is the state
# every deployment starts in and the state a new one is in on the day it is handed over. In it, the refusal
# left the fourth step of the macOS install — the one that decides whether HTTPS works at all — with no lane:
# the package was signed and notarised, the extension pre-approved, the configuration derived, and every
# tool on the Mac broken with nothing able to say why.
#
# So: the organization's own root when it has one, and the DEPLOYMENT's when it does not — named as such,
# because installing a shared root is a different act from installing your own and the operator has to know
# which they did.
if not rows:
    shared = (doc.get("default_root_pem") or "").strip()
    if not shared:
        sys.exit(
            "build_macos_interception_root_profile: this Edge signs nothing under %r and names no root of its\n"
            "  own either. It reports signing_scope=%s.\n"
            "  A profile built now would install a root that nothing mints under. Give the organization an\n"
            "  interception authority first, and make sure this Edge fetches its organizations from the control\n"
            "  plane (-tenant-transport-material-from-cp)." % (tenant, json.dumps(scope)))
    sys.stderr.write(
        "build_macos_interception_root_profile: %r has no interception authority of its own, so this profile\n"
        "  carries THE DEPLOYMENT'S root — the one every organization here is inspected under (signing_scope\n"
        "  effective=%s). Give the organization its own authority and rebuild to narrow it.\n"
        % (tenant, scope.get("effective", "?")))

# Every root this organization's devices are told to look for: the one in force, the ones being retired, and
# the one being moved to. See the note at the top about why one is not enough.
roles = []
if shared:
    roles.append(("in force (the deployment's own root, shared by every organization)", "", shared))
else:
    row = rows[0]
    if row.get("root_pem"):
        roles.append(("in force", row.get("root_common_name", ""), row["root_pem"]))
    for r in row.get("retiring") or []:
        roles.append(("retiring", r.get("common_name", ""), r.get("pem", "")))
    for r in row.get("incoming") or []:
        roles.append(("incoming", r.get("common_name", ""), r.get("pem", "")))
roles = [(role, cn, pem) for role, cn, pem in roles if (pem or "").strip()]
if not roles:
    sys.exit("build_macos_interception_root_profile: %r has no root certificate to distribute" % tenant)

def der_of(pem_text):
    body = "".join(l for l in pem_text.splitlines() if "-----" not in l)
    return base64.b64decode(body)

payloads, listed = [], []
for role, cn, pem_text in roles:
    der = der_of(pem_text)
    fp = hashlib.sha256(der).hexdigest()
    payloads.append({
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": "jp.co.lantern-networks.dsse.interception-root.%s.%s" % (tenant, fp[:16]),
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": cn or ("interception root %s" % fp[:16]),
        "PayloadDescription": "The authority this organization's inspected traffic is re-signed by (%s)." % role,
        "PayloadOrganization": "Lantern Networks, Inc.",
        "PayloadCertificateFileName": "%s-%s.cer" % (tenant, fp[:16]),
        "PayloadContent": der,
        # ★ NOT set to true. AllowAllAppsAccess grants every app on the machine access to the keychain item;
        # this is a public certificate that only needs to be TRUSTED, and widening keychain access for it
        # would be a permission granted for no reason anyone could name.
        "AllowAllAppsAccess": False,
    })
    # ★ SELF-SIGNED OR NOT decides how a Mac must be told to trust it — see the note this prints at the end.
    #   The certificate knows: its subject and its issuer are the same, or they are not.
    der_subject = pem_text  # kept as the PEM; openssl reads it below, out of a temp file per certificate
    listed.append((role, cn, fp, pem_text))

profile = {
    "PayloadType": "Configuration",
    "PayloadVersion": 1,
    # ★ PER ORGANIZATION. Two organizations' profiles must not collide on a Mac that serves both, and
    # replacing one must not remove the other's roots.
    "PayloadIdentifier": "jp.co.lantern-networks.dsse.interception-roots.%s" % tenant,
    "PayloadUUID": str(uuid.uuid4()).upper(),
    "PayloadDisplayName": "Lantern DSSE — inspection authority (%s)" % tenant,
    "PayloadDescription": ("Trusts the authority this organization's inspected traffic is re-signed by. "
                          "Without it every HTTPS request on this Mac fails once steering is on."),
    "PayloadOrganization": "Lantern Networks, Inc.",
    "PayloadScope": "System",
    "PayloadRemovalDisallowed": True,
    "PayloadContent": payloads,
}
with open(out, "wb") as fh:
    plistlib.dump(profile, fh)

# ★ READ IT BACK AND COMPARE. Generating from the Edge and then checking the generated file against what the
# Edge said is not redundant: it is the difference between meaning to write the right certificate and the
# right certificate being in the file. This is the check that would have caught a truncated base64 body,
# which installs as a profile and trusts nothing.
with open(out, "rb") as fh:
    back = plistlib.load(fh)
written = {hashlib.sha256(p["PayloadContent"]).hexdigest() for p in back["PayloadContent"]}
for role, cn, fp, _pem in listed:
    if fp not in written:
        sys.exit("build_macos_interception_root_profile: %s (%s) is not in the written profile" % (cn, fp[:16]))

print("==> wrote %s" % out)

# ★★★ AND THE EXACT COMMAND FOR EACH ONE, WITH THE VERB THAT WORKS FOR IT (2026-09-04, measured on a real
# Mac). This used to print one line with `trustRoot` in it, for every certificate. `trustRoot` says "this is
# a root"; an interception CA issued by the deployment's own root is an INTERMEDIATE, and macOS marked that
# way keeps looking for the issuer above it, does not find it, and refuses every chain — while
# `security find-certificate` finds it and `openssl s_client` prints its name. Every symptom says installed
# and the browser shows an error on every page.
import os, subprocess, tempfile
def self_signed(pem_text):
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem_text); path = fh.name
    try:
        def field(which):
            r = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-" + which],
                               capture_output=True, text=True)
            return r.stdout.split("=", 1)[1].strip() if "=" in r.stdout else ""
        subj, iss = field("subject"), field("issuer")
        return bool(subj) and subj == iss
    finally:
        os.unlink(path)

for role, cn, fp, pem_text in listed:
    print("    %-9s %s" % (role, cn))
    print("              %s" % fp)
print("")
print("    %d certificate(s), read from the node that signs and verified back out of the file." % len(listed))
print("")
print("    On a Mac that is NOT enrolled in an MDM, trust each of them by hand — the verb differs, and the")
print("    wrong one is accepted and does nothing:")
for role, cn, fp, pem_text in listed:
    verb = "trustRoot" if self_signed(pem_text) else "trustAsRoot"
    why = "self-signed" if verb == "trustRoot" else "issued by another authority, so it is an intermediate"
    print("      # %s — %s" % (cn, why))
    print("      sudo security add-trusted-cert -d -r %s -p ssl \\" % verb)
    print("        -k /Library/Keychains/System.keychain <the %s certificate>" % role.split(" (")[0])
PY

# Structural validation, in the tool MDM will effectively use.
plutil -lint "$out" >/dev/null || { echo "build_macos_interception_root_profile: the generated profile is not a valid plist" >&2; exit 1; }

cat <<'NOTE'

    Deliver it through MDM. ★ A com.apple.security.root payload delivered by an MDM the Mac is ENROLLED in
    installs the certificate as trusted. A profile double-clicked by hand installs the certificate and does
    NOT trust it — the same asymmetry as the system-extension payload — so an unmanaged Mac still needs the
    command printed above for each certificate, and that is a lab procedure, not an installation.

    ★ WHETHER THAT PAYLOAD TRUSTS AN INTERMEDIATE THE WAY IT TRUSTS A ROOT HAS NOT BEEN MEASURED HERE. The
    payload type is named for roots, and what a deployment announces is often not one (see below). On the
    first managed Mac, check the device rather than the profile:  security dump-trust-settings -d  — and if
    the certificate is listed with no SSL trust setting, this is the same failure the hand command has.

    ★★★ THE VERB IS NOT ALWAYS trustRoot, AND THE WRONG ONE FAILS SILENTLY (2026-09-04, measured on a real
    Mac). `trustRoot` says "this certificate is a root". An interception CA issued by the deployment's own
    root is an INTERMEDIATE, and macOS marked with trustRoot keeps looking for the issuer above it, does not
    find it, and refuses every chain — while `security find-certificate` finds the certificate and
    `openssl s_client` prints its name. Everything looks installed and the browser shows an error on every
    page. For a certificate that is not self-signed the verb is `trustAsRoot`.

    The agent reports which of the announced roots it actually found; ask the deployment rather than
    assuming this worked. And check the machine itself, which is the only place the answer is:

      security dump-trust-settings -d
NOTE
