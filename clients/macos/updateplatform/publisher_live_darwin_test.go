package updateplatform

// publisher_live_darwin_test.go — the same check, against the real tools and a real signed package, because
// every fixture in publisher_test.go is a belief about what pkgutil and spctl print and this is the file that
// finds out.
//
// It SKIPS when there is no package to test, which is most machines. It must never be softened into passing
// vacuously somewhere else: a skip says nothing was checked, and that is the honest answer when nothing was.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// livePackages returns the signed product archives this machine holds, newest first.
//
// DSSE_TEST_PKG overrides it for a single named package, which is how a build host checks the artefact it just
// produced.
func livePackages(t *testing.T) []string {
	t.Helper()
	if p := os.Getenv("DSSE_TEST_PKG"); p != "" {
		return []string{p}
	}
	matches, _ := filepath.Glob("../../../var/macos-ne-pkg*/*.pkg")
	type cand struct {
		path string
		at   int64
	}
	var cands []cand
	for _, m := range matches {
		// The component package is an input to the product archive and is not signed for distribution; testing it
		// would assert a refusal that says nothing about a release.
		if strings.Contains(filepath.Base(m), "-component") {
			continue
		}
		if st, err := os.Stat(m); err == nil {
			cands = append(cands, cand{m, st.ModTime().Unix()})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].at > cands[j].at })
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.path)
	}
	return out
}

// liveNotarizedPackage returns the newest package the real tools fully accept.
//
// ★ THE SPECIMEN IS CHOSEN BY WHAT THE TOOLS SAY, NOT BY THE FILENAME, and the reason is concrete: this
// repository's NEWEST local build (0.3.0) is signed and not notarized, because the notarization credentials
// went missing. A test that simply took the newest .pkg failed, and it was right to.
func liveNotarizedPackage(t *testing.T) string {
	t.Helper()
	for _, p := range livePackages(t) {
		if _, err := VerifyPublisher(p, PublisherRequirement{TeamID: realTeam}); err == nil {
			return p
		}
	}
	t.Skip("no notarized release on this machine — nothing to verify against")
	return ""
}

// liveSignedButUnnotarizedPackage returns a package that is correctly SIGNED by this team and was never
// notarized — which is a narrower thing than "not accepted", and the distinction was not academic: the first
// version of this selector took the first package that failed and got an ancient UNSIGNED build, so the test
// asserting "notarization is required" was really asserting "a signature is required" and would have passed
// with the notarization check deleted.
//
// ★ AND IT IS WHY spctl IS LOAD-BEARING. pkgutil prints no Notarization line at all for an unnotarized package
// — it does not say "no" — so the pkgutil half of this check has nothing to object to here and passes. Each
// tool covers precisely what the other misses: pkgutil catches modified payload bytes that Gatekeeper accepts,
// Gatekeeper catches the missing notarization that pkgutil is silent about.
func liveSignedButUnnotarizedPackage(t *testing.T) string {
	t.Helper()
	for _, p := range livePackages(t) {
		out, _ := runPublisherTool("/usr/sbin/pkgutil", "--check-signature", p)
		if out == "" || parsePkgutilSignature(out, realTeam) != nil {
			continue // unsigned, or somebody else's — a different failure from the one under test
		}
		if _, err := VerifyPublisher(p, PublisherRequirement{TeamID: realTeam}); err != nil {
			return p
		}
	}
	t.Skip("no signed-but-unnotarized package on this machine")
	return ""
}

func TestLiveARealReleaseIsAcceptedAndAnotherTeamIsNot(t *testing.T) {
	pkg := liveNotarizedPackage(t)

	note, err := VerifyPublisher(pkg, PublisherRequirement{TeamID: realTeam})
	if err != nil {
		t.Fatalf("the real tools refused a genuine release (%s): %v", pkg, err)
	}
	if !strings.Contains(note, realTeam) {
		t.Fatalf("the note should name the team that was verified: %s", note)
	}

	// The same bytes, a different expectation. This is the whole control: an attacker who can sign a manifest
	// still has to produce a package Apple issued a certificate for, to THIS team.
	if _, err := VerifyPublisher(pkg, PublisherRequirement{TeamID: "ZZ99AAAA11"}); err == nil {
		t.Fatal("a package from a different team than the device requires was accepted")
	} else if !strings.Contains(err.Error(), "not our bytes") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// ★★ THE FINDING THAT JUSTIFIES USING BOTH TOOLS (2026-08-13, measured on this machine). One byte was flipped in
// the middle of a genuine, notarized release and:
//
//	spctl --assess --type install -vv  →  accepted, source=Notarized Developer ID, origin=…(M4U8GSBL6C)
//	pkgutil --check-signature          →  Status: package is invalid (checksum did not verify)
//
// Gatekeeper's assessment validates the archive's signature and its stapled ticket, and neither covers the
// payload the way one would assume from the word "accepted". A check built on spctl alone — the obvious choice,
// and the one the design sketch reached for first — would have declared modified bytes to be a notarized
// release from the right company and handed them to a root installer.
func TestLiveATamperedReleaseIsRefusedEvenThoughGatekeeperAcceptsIt(t *testing.T) {
	pkg := liveNotarizedPackage(t)

	raw, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "tampered.pkg")
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Recorded, not asserted: this is Apple's behaviour, not ours, and pinning it would make the test fail the
	// day Apple tightens it — which would be good news. What must hold is our verdict, below.
	if out, _ := runPublisherTool("/usr/sbin/spctl", "--assess", "--type", "install", "-vv", tampered); out != "" {
		if parseSpctlAssessment(out, realTeam) == nil {
			t.Logf("as expected and as the comment says: Gatekeeper still accepts the tampered package —\n%s", out)
		} else {
			t.Logf("Gatekeeper now refuses the tampered package too; the payload check below is no longer the only "+
				"thing catching this —\n%s", out)
		}
	}

	if _, err := VerifyPublisher(tampered, PublisherRequirement{TeamID: realTeam}); err == nil {
		t.Fatal("a package with a modified payload was accepted for installation as root")
	} else if !strings.Contains(err.Error(), "checksum did not verify") {
		t.Fatalf("the refusal should name the payload check that caught it, got: %v", err)
	}
}

// A device with no requirement must not be silently fine, and must not be refused either: it is an older
// install, and refusing there strands exactly the fleet that needs to reach a build that has the check.
func TestLiveAnUnconfiguredDeviceInstallsButSaysWhatItIsMissing(t *testing.T) {
	pkg := liveNotarizedPackage(t)
	note, err := VerifyPublisher(pkg, PublisherRequirement{})
	if err != nil {
		t.Fatalf("an unconfigured device must still be able to update: %v", err)
	}
	if !strings.Contains(note, "update_publisher_team_id") {
		t.Fatalf("the note must name the field that is missing: %s", note)
	}
}

// ★★ A REAL SPECIMEN OF THE THING THIS CHECK IS FOR, sitting in this repository (2026-08-13).
//
// var/macos-ne-pkg/LanternDsseAgent-0.3.0-…pkg is signed by the right Developer ID Installer certificate, from
// the right team, and was never notarized — the credentials for it went missing. So it is a genuine artefact of
// this product's own build host that did not come out of the full pipeline, and it is the newest package on
// disk. Before this check, nothing on a device could tell it apart from a release.
//
// It is also the operational consequence stated plainly: turning the publisher requirement on means packages
// built while notarization is unavailable cannot install. That is the intended behaviour and it has a cost, and
// the cost belongs in a test rather than in a surprise.
func TestLiveASignedButUnnotarizedBuildOfOurOwnIsRefused(t *testing.T) {
	pkg := liveSignedButUnnotarizedPackage(t)
	_, err := VerifyPublisher(pkg, PublisherRequirement{TeamID: realTeam})
	if err == nil {
		t.Fatalf("%s is signed but not notarized, and it was accepted for install as root", pkg)
	}
	t.Logf("refused %s: %v", filepath.Base(pkg), err)
}
