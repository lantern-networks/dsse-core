package updateplatform

// publisher.go — the second question, asked on the device: not "which version may run" but "who built these
// bytes".
//
// ★ WHY THIS EXISTS (2026-08-13, the agent publishing-authority design). Until now the
// signed manifest was the ONLY thing standing between a fetched file and `installer -pkg -target /` as root.
// `installer` run as root does not care whether a package is signed — Gatekeeper's assessment is a
// quarantine-time story and nothing quarantines a file a daemon downloaded. So whoever held the update key
// held root on every Mac in the fleet, and the operator's alternative — two-person approval on publishing —
// was rejected as too heavy for this stage of the product.
//
// This is the replacement, and it is cheaper than approval because the defence was already bought and simply
// never asked for: the packages are signed with a Developer ID Installer certificate and notarized, with the
// ticket stapled by the build. Two keys, in two custodies:
//
//	update manifest key   — says WHICH VERSION may run  — lives in the CP's HSM token
//	package signing key   — says WHO BUILT THESE BYTES  — lives with Apple Developer ID, on the build side
//
// An attacker who takes the control plane gets the first and not the second, so the worst they can choose is
// one of the versions this publisher really built. That is a bounded, recoverable incident. Arbitrary code as
// root is not.
//
// ★ IT IS SEPARATE FROM THE DIGEST CHECK AND NOT A DUPLICATE OF IT. VerifyStaged proves the bytes are the ones
// the manifest names. This proves the manifest names bytes that Lantern built. A compromised signer passes the
// first check trivially — it writes the digest of whatever it wants.
//
// ★★ AND THE TWO-TOOL SHAPE IS macOS's, NOT A RULE (2026-08-13, measured on win-dev-1 after this file asked
// for the experiment). The same test on Windows — flip one byte in the middle of a signed MSI — makes
// WinVerifyTrust return TRUST_E_BAD_DIGEST. Authenticode there answers BOTH "who built this" and "have the
// covered bytes changed", so the second check macOS needs has nothing to do on that platform. Scoped as they
// scoped it: that shows the middle payload byte is covered, not that every MSI modification is.
//
// Recorded here because the next person writing the Windows check will read this file first, and copying the
// two-tool rationale across would be copying a fact about Gatekeeper into a platform that does not share it.
//
// The parsing lives here without a build tag, and only the two exec calls are darwin-only: what makes this
// check wrong is misreading `pkgutil`'s output, and that must be testable on any machine, from captured real
// output, rather than only on the platform where a mistake installs something.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PublisherRequirement is what this device demands of a package before a privileged installer is pointed at it.
//
// One field, deliberately. The Team ID is the whole identity: it is the part of a Developer ID subject Apple
// binds to an enrolled organisation and will not issue to someone else, while the display name beside it
// ("Lantern Networks, Inc.") is cosmetic and could be matched by a certificate issued to a similarly-named
// company. Notarization is not a second field because it is not a separate decision — an unnotarized package
// from the right team means the build pipeline was bypassed, which is exactly the event this check is for.
type PublisherRequirement struct {
	// TeamID is the ten-character Apple Team ID, e.g. M4U8GSBL6C. Empty means this device has no requirement,
	// which is a state the caller must treat as a defect rather than as permission — see RequirementMissingNote.
	TeamID string
}

// Configured reports whether this device actually has a publisher to check against.
func (r PublisherRequirement) Configured() bool { return r.TeamID != "" }

// RequirementMissingNote is what an operator needs to read when a device has no publisher requirement. It is a
// sentence rather than a flag because the previous version of this failure — "no update-signing key is pinned"
// — was correct, was logged every thirty minutes, and was never read by anyone, so the wording has to carry
// the consequence and not just the state.
const RequirementMissingNote = "★ this device names no update_publisher_team_id, so a package is installed as " +
	"root on the strength of the manifest signature ALONE — anyone able to sign a manifest can run arbitrary " +
	"code here. Set update_publisher_team_id in the agent configuration."

type agentConfigPublisher struct {
	TeamID string `json:"update_publisher_team_id"`
}

// LoadPublisherRequirement reads the expected publisher from the same agent configuration that carries the
// signing keys.
//
// The same file on purpose: this is tenant-specific material that arrives the way all the other tenant-specific
// material does, and a second file that must agree with the first is a way to be configured and unconfigured at
// once. It is also the file the installer already refuses to install without, and whose root ownership the
// package already enforces.
//
// An unreadable or malformed configuration is an ERROR, never an empty requirement. Those are the same value in
// Go and must not be the same outcome here: "this operator chose not to pin a publisher" and "this device
// cannot tell what it was configured with" differ by exactly the case an attacker creates.
func LoadPublisherRequirement(path string) (PublisherRequirement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PublisherRequirement{}, fmt.Errorf("read the agent configuration %s: %w", path, err)
	}
	var cfg agentConfigPublisher
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return PublisherRequirement{}, fmt.Errorf("the agent configuration %s is not valid JSON: %w", path, err)
	}
	id := strings.TrimSpace(cfg.TeamID)
	if id == "" {
		return PublisherRequirement{}, nil
	}
	if err := validTeamID(id); err != nil {
		// Refused rather than carried, because a malformed Team ID cannot match any real certificate: the check
		// would then refuse every package, including the good one, and the fleet would stop updating with a
		// message about signatures. Better to name the typo.
		return PublisherRequirement{}, fmt.Errorf("update_publisher_team_id %q is not an Apple Team ID: %w", id, err)
	}
	return PublisherRequirement{TeamID: strings.ToUpper(id)}, nil
}

// validTeamID checks the shape Apple issues: ten characters, uppercase letters and digits.
func validTeamID(id string) error {
	if len(id) != 10 {
		return fmt.Errorf("an Apple Team ID is 10 characters, this is %d", len(id))
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		default:
			return fmt.Errorf("it contains %q, and a Team ID is letters and digits only", r)
		}
	}
	return nil
}

// pkgutilTrustedStatus is the ONE status line this product's packages produce.
//
// An allowlist of one, rather than a denylist of the bad forms, because `pkgutil` has other statuses
// ("signed by a certificate trusted by Mac OS X", "signed Apple Software") that are perfectly true statements
// about packages nobody here built, and because a status this code has never seen must not be read as approval.
const pkgutilTrustedStatus = "signed by a developer certificate issued by Apple for distribution"

// developerIDInstallerPrefix is the certificate TYPE that may sign a product archive for distribution outside
// the App Store. Requiring it, rather than only the Team ID, keeps a certificate the same team holds for a
// different purpose — a Developer ID Application cert, say, or an installer cert from a test enrolment — from
// standing in for the one the release pipeline uses.
const developerIDInstallerPrefix = "Developer ID Installer:"

// parsePkgutilSignature reads `pkgutil --check-signature <pkg>` and answers whether the leaf is a Developer ID
// Installer certificate belonging to teamID.
//
// This is the OFFLINE, cryptographic half: pkgutil verifies the CMS signature over the archive and the chain to
// Apple's root before it prints any of this, so a match here means the bytes on disk were signed by a
// certificate Apple issued to that team. It works on a laptop with no network, which matters — a check that
// needs the internet to pass would stop updates precisely when a device has been off the network longest.
func parsePkgutilSignature(out, teamID string) error {
	lines := strings.Split(out, "\n")

	status := ""
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(t, "Status:"); ok {
			status = strings.TrimSpace(rest)
			break
		}
	}
	switch {
	case status == "":
		return fmt.Errorf("pkgutil printed no Status line, so nothing here says the package is signed at all "+
			"(output: %s)", firstLines(out, 3))
	case status != pkgutilTrustedStatus:
		return fmt.Errorf("the package's signature status is %q, and the only status this product's releases "+
			"carry is %q", status, pkgutilTrustedStatus)
	}

	// ★ pkgutil STATES THE NOTARIZATION TOO, and it is worth reading even though spctl is asked next: this line
	// comes from the ticket stapled to the archive, so it does not depend on the machine's Gatekeeper policy —
	// which is state an attacker with root can change. It is checked only WHEN PRESENT: older macOS builds of
	// pkgutil print no such line, and demanding it there would refuse every package on those machines.
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		rest, ok := strings.CutPrefix(t, "Notarization:")
		if !ok {
			continue
		}
		if n := strings.TrimSpace(rest); !strings.Contains(n, "trusted by the Apple notary service") {
			return fmt.Errorf("the package's stapled notarization reads %q — a release that did not come through "+
				"this product's notarized build is not one to install as root", n)
		}
		break
	}

	// The leaf is entry 1 of the chain. Deeper entries are the intermediate and Apple's root, and a package
	// whose LEAF is the Apple root would be a parse error rather than a triumph, so the position is checked and
	// not searched for.
	leaf, ok := chainEntry(lines, 1)
	if !ok {
		return fmt.Errorf("pkgutil printed a trusted status but no certificate chain, which is not an output "+
			"shape this check understands (output: %s)", firstLines(out, 6))
	}
	if !strings.HasPrefix(leaf, developerIDInstallerPrefix) {
		return fmt.Errorf("the signing certificate is %q, not a %s certificate — a package for distribution is "+
			"signed by the installer certificate, and something else signed this one", leaf, developerIDInstallerPrefix)
	}
	got, ok := teamIDFromSubject(leaf)
	if !ok {
		return fmt.Errorf("no Apple Team ID could be read from the signing certificate %q", leaf)
	}
	if !strings.EqualFold(got, teamID) {
		return fmt.Errorf("the package was signed by team %s and this device only installs packages from team "+
			"%s — the manifest may say to install it, but these are not our bytes", got, teamID)
	}
	return nil
}

// chainEntry returns the subject of the nth certificate in pkgutil's "Certificate Chain:" block.
//
// The lines look like `    1. Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)` with the details
// indented beneath, so the entry is found by its number-and-dot prefix rather than by position in the file.
func chainEntry(lines []string, n int) (string, bool) {
	want := fmt.Sprintf("%d. ", n)
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(t, want); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// teamIDFromSubject pulls M4U8GSBL6C out of `Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)`.
//
// The LAST parenthesised group is taken, because an organisation name may itself contain parentheses and Apple
// appends the team identifier at the end.
func teamIDFromSubject(subject string) (string, bool) {
	close := strings.LastIndex(subject, ")")
	if close < 0 {
		return "", false
	}
	open := strings.LastIndex(subject[:close], "(")
	if open < 0 {
		return "", false
	}
	id := strings.TrimSpace(subject[open+1 : close])
	if validTeamID(id) != nil {
		return "", false
	}
	return id, true
}

// parseSpctlAssessment reads `spctl --assess --type install -vv <pkg>` and answers whether Gatekeeper accepts
// the package as NOTARIZED and from teamID.
//
// This is the half pkgutil cannot answer. A Developer ID certificate proves who signed; notarization proves the
// bytes went through the build-and-submit pipeline and were scanned, and — the operational part — that Apple
// can revoke them fleet-wide if this product ever ships something malicious. The build staples the ticket
// (`stapler staple` + `stapler validate` in build_macos_ne_pkg.sh), so this too is answerable offline.
//
// ★ "accepted" ALONE IS NOT ENOUGH. spctl accepts a plain Developer ID package on a system whose policy has been
// relaxed, and prints `source=Developer ID` rather than `source=Notarized Developer ID`. Reading only the verdict
// would let a locally re-signed package through on exactly the machines an attacker had already touched.
func parseSpctlAssessment(out, teamID string) error {
	var verdict, source, origin string
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasSuffix(t, ": accepted"):
			verdict = "accepted"
		case strings.HasSuffix(t, ": rejected"):
			verdict = "rejected"
		}
		if rest, ok := strings.CutPrefix(t, "source="); ok {
			source = strings.TrimSpace(rest)
		}
		if rest, ok := strings.CutPrefix(t, "origin="); ok {
			origin = strings.TrimSpace(rest)
		}
	}
	switch verdict {
	case "":
		return fmt.Errorf("Gatekeeper returned no verdict for this package, so its notarization is unknown — and "+
			"unknown is not the same as fine (output: %s)", firstLines(out, 3))
	case "rejected":
		return fmt.Errorf("Gatekeeper REJECTED this package: %s", firstLines(out, 3))
	}
	if !strings.Contains(source, "Notarized") {
		return fmt.Errorf("Gatekeeper accepted the package but as %q rather than a notarized one — a release that "+
			"skipped notarization did not come out of this product's build pipeline", source)
	}
	got, ok := teamIDFromSubject(origin)
	if !ok {
		return fmt.Errorf("Gatekeeper reported the origin as %q, which names no Apple Team ID", origin)
	}
	if !strings.EqualFold(got, teamID) {
		return fmt.Errorf("Gatekeeper reports the notarized origin as team %s, and this device installs only team "+
			"%s", got, teamID)
	}
	return nil
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " / ")
}

// DescribePublisherRequirement is the one-line answer for --status and for the daemon's start banner.
//
// It exists because the requirement is a security control whose ABSENCE is invisible: a device with no
// publisher pinned updates perfectly happily, and looks identical to one that checks. This product has already
// shipped that exact shape once — an update daemon that could never update, refusing correctly, into a log
// nobody read.
func DescribePublisherRequirement(agentConfigPath string) string {
	req, err := LoadPublisherRequirement(agentConfigPath)
	switch {
	case err != nil:
		return "★ UNREADABLE (" + err.Error() + ") — no package will be installed until this is fixed, because a " +
			"device that cannot say whose packages it accepts must not accept any"
	case !req.Configured():
		return RequirementMissingNote
	default:
		return "notarized Developer ID Installer, team " + req.TeamID + " (checked immediately before the installer runs)"
	}
}
