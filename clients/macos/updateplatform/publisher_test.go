package updateplatform

// publisher_test.go — the fixtures here are REAL OUTPUT, captured on 2026-08-13 from
// var/macos-ne-pkg/LanternDsseAgent-0.2.9-20260812003535.pkg on the build Mac. That matters more than usual for
// this file: everything it decides is a guess about the shape of another program's output, and a hand-written
// fixture would test my belief about pkgutil rather than pkgutil.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The genuine article, trimmed only where the fingerprint bytes repeat.
const realPkgutil = `Package "LanternDsseAgent-0.2.9-20260812003535.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2026-08-12 00:35:52 +0000
   Certificate Chain:
    1. Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)
       Expires: 2027-02-01 22:12:15 +0000
       SHA256 Fingerprint:
           44 5D 83 83 75 36 4D FD E8 7F 13 E8 99 7B 5F AA 0C CA 3D 60 FE 6D
           E0 82 F7 3E 56 30 F7 AF 01 59
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
       Expires: 2027-02-01 22:12:15 +0000
       SHA256 Fingerprint:
           7A FC 9D 01 A6 2F 03 A2 DE 96 37 93 6D 4A FE 68 09 0D 2D E1 8D 03 F2
       ------------------------------------------------------------------------
    3. Apple Root CA
       Expires: 2035-02-09 21:40:36 +0000
`

// The leading path is rewritten to a machine-independent one: spctl echoes whatever path it was handed, the
// parse only reads the verdict after the colon, and a home directory in a fixture pins the fixture to one
// account.
const realSpctl = `/opt/dsse/LanternDsseAgent-0.2.9-20260812003535.pkg: accepted
source=Notarized Developer ID
origin=Developer ID Installer: Lantern Networks, Inc. (M4U8GSBL6C)`

const realTeam = "M4U8GSBL6C"

func TestTheRealPackageThisProductShipsIsAccepted(t *testing.T) {
	if err := parsePkgutilSignature(realPkgutil, realTeam); err != nil {
		t.Fatalf("the signature of a genuine release was refused: %v", err)
	}
	if err := parseSpctlAssessment(realSpctl, realTeam); err != nil {
		t.Fatalf("the notarization of a genuine release was refused: %v", err)
	}
}

// ★ The check must refuse a package from a DIFFERENT team even though everything else about it is impeccable:
// really signed, really notarized, really from a real Apple-enrolled company. That is the whole point — the
// manifest key says which version, this says whose bytes, and a compromised manifest key can only ever name
// bytes somebody actually built.
func TestAPerfectlyValidPackageFromAnotherCompanyIsRefused(t *testing.T) {
	other := strings.ReplaceAll(realPkgutil, realTeam, "ZZ99AAAA11")
	err := parsePkgutilSignature(other, realTeam)
	if err == nil {
		t.Fatal("a signed, notarized package from another Apple team was accepted for install as root")
	}
	if !strings.Contains(err.Error(), "not our bytes") {
		t.Fatalf("the refusal must say what happened, got: %v", err)
	}
	if err := parseSpctlAssessment(strings.ReplaceAll(realSpctl, realTeam, "ZZ99AAAA11"), realTeam); err == nil {
		t.Fatal("Gatekeeper's report naming another team was accepted")
	}
}

func TestSignatureShapesThatMustNotInstall(t *testing.T) {
	cases := []struct {
		name, out, wantSays string
	}{
		{
			// The output for an unsigned package. It has a Status line, so anything checking only for the
			// PRESENCE of one passes here.
			name:     "unsigned",
			out:      "Package \"x.pkg\":\n   Status: no signature\n",
			wantSays: "signature status",
		},
		{
			name:     "signed by an untrusted certificate",
			out:      "Package \"x.pkg\":\n   Status: signed by untrusted certificate\n",
			wantSays: "signature status",
		},
		{
			// ★ A status this code has never seen. Trusted by macOS is a true statement about a package that did
			// not come from a Developer ID pipeline, and the allowlist is what keeps "unrecognised" from meaning
			// "fine".
			name:     "trusted, but not a Developer ID distribution",
			out:      "Package \"x.pkg\":\n   Status: signed by a certificate trusted by Mac OS X\n",
			wantSays: "signature status",
		},
		{
			name:     "no output at all",
			out:      "",
			wantSays: "no Status line",
		},
		{
			// Right team, right notarization, WRONG certificate type: a Developer ID Application certificate the
			// same company holds. Apple issues both to one team, and only one of them signs a release.
			name:     "the same team's application certificate",
			out:      strings.Replace(realPkgutil, "1. Developer ID Installer:", "1. Developer ID Application:", 1),
			wantSays: "not a Developer ID Installer",
		},
		{
			// Signed and trusted, but the staple says the notarization is not good. Reading only the Status line
			// would accept it.
			name:     "stapled ticket that is not trusted",
			out:      strings.Replace(realPkgutil, "trusted by the Apple notary service", "unknown", 1),
			wantSays: "stapled notarization",
		},
		{
			name:     "a status but no chain",
			out:      "Package \"x.pkg\":\n   Status: " + pkgutilTrustedStatus + "\n",
			wantSays: "no certificate chain",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := parsePkgutilSignature(c.out, realTeam)
			if err == nil {
				t.Fatal("accepted, and this package would then be installed as root")
			}
			if !strings.Contains(err.Error(), c.wantSays) {
				t.Fatalf("the refusal should say %q, got: %v", c.wantSays, err)
			}
		})
	}
}

// ★ THE CASE THAT MOTIVATES READING source=. A Developer ID package that never went through notarization is
// ACCEPTED by spctl on a machine whose assessment policy has been relaxed — and relaxing it is something an
// attacker with root does. The verdict alone is not the answer.
func TestAnAcceptedButUnnotarizedPackageIsRefused(t *testing.T) {
	out := strings.Replace(realSpctl, "source=Notarized Developer ID", "source=Developer ID", 1)
	err := parseSpctlAssessment(out, realTeam)
	if err == nil {
		t.Fatal("an accepted-but-unnotarized package was allowed")
	}
	if !strings.Contains(err.Error(), "skipped notarization") {
		t.Fatalf("the refusal should name what is missing, got: %v", err)
	}
}

func TestGatekeeperShapesThatMustNotInstall(t *testing.T) {
	cases := []struct{ name, out, wantSays string }{
		{"rejected", "x.pkg: rejected\nsource=obsolete resource envelope", "REJECTED"},
		{"no verdict at all", "", "no verdict"},
		{"accepted with no origin", "x.pkg: accepted\nsource=Notarized Developer ID", "names no Apple Team ID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := parseSpctlAssessment(c.out, realTeam)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.wantSays) {
				t.Fatalf("want %q, got: %v", c.wantSays, err)
			}
		})
	}
}

// An organisation name may itself contain parentheses; the team identifier is the LAST group.
func TestTeamIDIsReadFromTheEndOfTheSubject(t *testing.T) {
	got, ok := teamIDFromSubject("Developer ID Installer: Lantern (Japan) K.K. (M4U8GSBL6C)")
	if !ok || got != realTeam {
		t.Fatalf("got %q ok=%t", got, ok)
	}
	if _, ok := teamIDFromSubject("Developer ID Installer: No Team Here"); ok {
		t.Fatal("a subject with no team identifier reported one")
	}
	// Not every parenthesised tail is a Team ID, and treating one as such would compare a company's suffix
	// against the configured id and refuse a genuine package with a confusing message.
	if _, ok := teamIDFromSubject("Developer ID Installer: Lantern Networks, Inc. (formerly DSSE)"); ok {
		t.Fatal("a parenthesised phrase was read as a Team ID")
	}
}

func TestTheRequirementIsReadFromTheAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.json")

	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(`{"edge_url":"http://e","update_publisher_team_id":"m4u8gsbl6c"}`)
	req, err := LoadPublisherRequirement(path)
	if err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
	// Team IDs are printed uppercase by Apple's tools and typed either way by people. The comparison is
	// case-insensitive anyway; normalising means the --status line does not vary with how it was typed.
	if req.TeamID != realTeam || !req.Configured() {
		t.Fatalf("got %+v", req)
	}

	// ★ NOT CONFIGURED AND NOT READABLE MUST NOT BE THE SAME ANSWER. They are the same zero value in Go, which is
	// how this class of defect gets written, and one of them means "an old device" while the other means "this
	// device cannot state what it trusts".
	write(`{"edge_url":"http://e"}`)
	req, err = LoadPublisherRequirement(path)
	if err != nil || req.Configured() {
		t.Fatalf("an absent field must be a clean empty requirement, got %+v err=%v", req, err)
	}
	if _, err := LoadPublisherRequirement(filepath.Join(dir, "gone.json")); err == nil {
		t.Fatal("a missing configuration reported no requirement, which reads as permission")
	}
	write(`{not json`)
	if _, err := LoadPublisherRequirement(path); err == nil {
		t.Fatal("an unparseable configuration reported no requirement")
	}

	// A typo cannot match any certificate, so carrying it would refuse every package with a message about
	// signatures rather than about the typo.
	write(`{"update_publisher_team_id":"M4U8GSBL"}`)
	if _, err := LoadPublisherRequirement(path); err == nil {
		t.Fatal("a short Team ID was accepted")
	}
	write(`{"update_publisher_team_id":"M4U8GSBL6C "}`)
	if req, err := LoadPublisherRequirement(path); err != nil || req.TeamID != realTeam {
		t.Fatalf("trailing whitespace should not be a misconfiguration: %+v %v", req, err)
	}
}

func TestTheStatusLineTellsAnOperatorWhichOfTheThreeStatesThisDeviceIsIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_config.json")

	if got := DescribePublisherRequirement(filepath.Join(dir, "absent.json")); !strings.Contains(got, "UNREADABLE") {
		t.Fatalf("an unreadable config must be distinguishable at a glance: %s", got)
	}
	if err := os.WriteFile(path, []byte(`{"edge_url":"http://e"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := DescribePublisherRequirement(path)
	if !strings.Contains(got, "update_publisher_team_id") || !strings.Contains(got, "arbitrary code") {
		t.Fatalf("the missing state must name the field AND the consequence: %s", got)
	}
	if err := os.WriteFile(path, []byte(`{"update_publisher_team_id":"`+realTeam+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DescribePublisherRequirement(path); !strings.Contains(got, realTeam) {
		t.Fatalf("a configured device should print its team: %s", got)
	}
}
