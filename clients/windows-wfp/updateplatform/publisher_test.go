package updateplatform

// publisher_test.go — the judgement, exercised on any machine.
//
// It runs off-Windows on purpose: what makes this gate wrong is a comparison, and a comparison that can only
// be tested on the platform where a mistake installs something as SYSTEM is one nobody tests. The wintrust
// call it feeds on is the part that needs a Windows box, and it is the part least likely to be subtly wrong.
//
// ★ EVERY REFUSAL IS ASSERTED TO BE A DIFFERENT REFUSAL. An implementation that refused everything for one
// reason would satisfy a suite that only checked "an error came back", and this file's whole subject is a
// negative check — see the same rule in agentupdate's manifest tests, which is where this product learned it.

import (
	"errors"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/authenticode"
)

// lantern is the shape a real verdict has on a correctly signed release: valid, with an Org and a leaf hash.
func lantern() authenticode.Sig {
	return authenticode.Sig{
		Valid:      true,
		Publisher:  "Lantern Networks, Inc.",
		Org:        "Lantern Networks, Inc.",
		Thumbprint: "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899",
	}
}

func TestAnUnsetRequirementInstallsAndSaysSo(t *testing.T) {
	req := ParsePublisherRequirement("   ")
	if req.Configured() {
		t.Fatal("an empty requirement must not read as configured")
	}
	if req.Defect != "" {
		t.Fatalf("empty is a CHOICE nobody has made, not a defect; got %q", req.Defect)
	}
	if got := req.Describe(); got != RequirementMissingNote {
		t.Fatalf("an unset requirement must describe itself as the missing note, got %q", got)
	}
}

// ★ The two loose forms of the exclusion vocabulary must be refused BY NAME, and each must say what to write
// instead. Folding them into the generic "names no form" answer would be correct and useless: an operator who
// wrote `publisher:Lantern` did not mistype, they used a form that means something weaker than they think.
func TestTheLooseExclusionFormsAreRefusedWithTheirOwnReason(t *testing.T) {
	pub := ParsePublisherRequirement("publisher:Lantern")
	sig := ParsePublisherRequirement("signed:dsse-agent.msi")
	junk := ParsePublisherRequirement("Lantern Networks, Inc.")

	for name, req := range map[string]PublisherRequirement{"publisher:": pub, "signed:": sig, "bare": junk} {
		if req.Configured() {
			t.Fatalf("%s must not configure a gate", name)
		}
		if req.Defect == "" {
			t.Fatalf("%s must carry a defect saying why", name)
		}
		if !strings.Contains(req.Defect, "subject:") {
			t.Fatalf("%s must name the form to use instead; got %q", name, req.Defect)
		}
	}
	if pub.Defect == sig.Defect || pub.Defect == junk.Defect || sig.Defect == junk.Defect {
		t.Fatal("the three refusals must be distinguishable — an operator fixes each one differently")
	}
	if !strings.Contains(pub.Defect, "SUBSTRING") {
		t.Fatalf("the publisher: refusal must say WHY it is weak, got %q", pub.Defect)
	}
}

// ★ A DEFECT DESCRIBES ITSELF AS "NOT CHECKED", NEVER AS A REFUSAL TO INSTALL. The requirement travels inside
// the MSI, so refusing on a malformed one would make the only repair path the one being refused. If this test
// ever has to change, the deadlock is what is being reintroduced.
func TestAMalformedRequirementDoesNotStopInstalling(t *testing.T) {
	req := ParsePublisherRequirement("thumbprint:not-a-hash")
	if req.Configured() {
		t.Fatal("a malformed thumbprint must not arm the gate")
	}
	if req.Defect == "" {
		t.Fatal("a malformed thumbprint must be reported as a defect")
	}
	d := req.Describe()
	if !strings.Contains(d, "NOT CHECKED") {
		t.Fatalf("a defect must announce that nothing is being checked, got %q", d)
	}
	if !strings.Contains(d, "install") {
		t.Fatalf("a defect must say packages still install, or an operator will believe they are protected: %q", d)
	}
	// And the reason names the actual value, so the typo is visible as itself.
	if !strings.Contains(req.Defect, "not-a-hash") {
		t.Fatalf("the defect must quote what was configured, got %q", req.Defect)
	}
}

func TestSubjectMatchesTheSigningOrganisation(t *testing.T) {
	req := ParsePublisherRequirement("subject:Lantern Networks, Inc.")
	if !req.Configured() || req.Kind != FormSubject {
		t.Fatalf("subject: must configure a subject gate, got %+v", req)
	}
	if err := req.Check(lantern()); err != nil {
		t.Fatalf("the release publisher must satisfy its own requirement: %v", err)
	}
	// Case-insensitively: certificate subjects are names, and a capitalisation difference is not an identity.
	if err := ParsePublisherRequirement("subject:lantern networks, inc.").Check(lantern()); err != nil {
		t.Fatalf("a case difference is not a different organisation: %v", err)
	}
	other := lantern()
	other.Org = "Some Other Company K.K."
	err := req.Check(other)
	if !errors.Is(err, ErrPublisherUntrusted) {
		t.Fatalf("another organisation's package must be refused as untrusted, got %v", err)
	}
	if !strings.Contains(err.Error(), "Some Other Company K.K.") {
		t.Fatalf("the refusal must name who DID sign it, got %v", err)
	}
}

// ★ THE THREE WAYS A SUBJECT CHECK CAN FAIL MUST READ DIFFERENTLY. "not signed", "signed by someone else" and
// "signed, but the signer could not be read" send an operator to three different places — and the third is the
// one most likely to be a fault in THIS code rather than in the package, which is why its message says so.
func TestTheSubjectFailuresAreTold_Apart(t *testing.T) {
	req := ParsePublisherRequirement("subject:Lantern Networks, Inc.")

	unsigned := req.Check(authenticode.Sig{})
	unreadable := req.Check(authenticode.Sig{Valid: true})
	wrong := lantern()
	wrong.Org = "Someone Else"
	mismatch := req.Check(wrong)

	for name, err := range map[string]error{"unsigned": unsigned, "unreadable": unreadable, "mismatch": mismatch} {
		if !errors.Is(err, ErrPublisherUntrusted) {
			t.Fatalf("%s must refuse as untrusted, got %v", name, err)
		}
	}
	if unsigned.Error() == unreadable.Error() || unsigned.Error() == mismatch.Error() || unreadable.Error() == mismatch.Error() {
		t.Fatal("the three refusals must not render the same — a check that cannot tell its failures apart passes " +
			"just as happily when it is refusing everything for the wrong reason")
	}
	if !strings.Contains(unreadable.Error(), "the fault is in this check") {
		t.Fatalf("a valid signature whose signer cannot be read must name this gate as the likely fault, got %v", unreadable)
	}
}

// ★ AN IDENTITY THAT MATCHES ON AN INVALID SIGNATURE IS STILL A REFUSAL. The fields are best-effort and are
// populated even when trust fails; reading them first would accept a tampered package whose certificate still
// parses. Order is the property being tested, and it is invisible in the happy path.
func TestAMatchingIdentityCannotRescueAnInvalidSignature(t *testing.T) {
	s := lantern()
	s.Valid = false
	for _, id := range []string{"subject:Lantern Networks, Inc.", "thumbprint:" + s.Thumbprint} {
		err := ParsePublisherRequirement(id).Check(s)
		if !errors.Is(err, ErrPublisherUntrusted) {
			t.Fatalf("%s: an untrusted signature must be refused whatever its subject says, got %v", id, err)
		}
		if !strings.Contains(err.Error(), "trusted root") {
			t.Fatalf("%s: the refusal must be the SIGNATURE one, not an identity mismatch: %v", id, err)
		}
	}
}

func TestThumbprintIsNormalisedAndBounded(t *testing.T) {
	want := lantern().Thumbprint
	// Every Windows UI shows a thumbprint colon-separated and uppercase, and somebody will paste that.
	spaced := "AA:11:BB:22:CC:33:DD:44:EE:55:FF:66:00:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	req := ParsePublisherRequirement("thumbprint:" + spaced)
	if !req.Configured() || req.Want != want {
		t.Fatalf("a pasted thumbprint must normalise to %s, got %+v", want, req)
	}
	if err := req.Check(lantern()); err != nil {
		t.Fatalf("the pinned certificate must satisfy its own pin: %v", err)
	}
	// A SHA-1 thumbprint is the mistake most likely to be made here — it is what older Windows UI shows — and
	// it must be named at parse time rather than refusing every package for ever.
	sha1ish := ParsePublisherRequirement("thumbprint:" + strings.Repeat("ab", 20))
	if sha1ish.Configured() {
		t.Fatal("a 40-character thumbprint must not arm the gate")
	}
	if !strings.Contains(sha1ish.Defect, "64 hex") {
		t.Fatalf("the defect must say what length is expected, got %q", sha1ish.Defect)
	}
}

// ★ A CERTIFICATE RENEWAL LOOKS EXACTLY LIKE AN ATTACK TO A THUMBPRINT PIN, and the fleet will meet the first
// far more often than the second. The refusal has to say so, or an operator diagnoses a compromise for an hour
// and finds a reissued certificate.
func TestAThumbprintMismatchNamesTheRenewalCase(t *testing.T) {
	req := ParsePublisherRequirement("thumbprint:" + strings.Repeat("11", 32))
	err := req.Check(lantern())
	if !errors.Is(err, ErrPublisherUntrusted) {
		t.Fatalf("a different certificate must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "RENEWAL") || !strings.Contains(err.Error(), "subject:") {
		t.Fatalf("the refusal must offer the durable form, got %v", err)
	}
}

// ★ A REQUIREMENT THIS BUILD DOES NOT UNDERSTAND IS NOT A SATISFIED ONE. Unreachable through
// ParsePublisherRequirement today; asserted because the default arm of a switch on a security decision is
// where the next form gets added, and "fall through to nil" is how it would ship permissive.
func TestAnUnrecognisedRequirementRefuses(t *testing.T) {
	err := PublisherRequirement{Kind: "issuer:", Want: "x", Raw: "issuer:x"}.Check(lantern())
	if !errors.Is(err, ErrPublisherUntrusted) {
		t.Fatalf("an unknown requirement kind must refuse, got %v", err)
	}
}

func TestDescribeTellsAnOperatorWhichPinTheyChose(t *testing.T) {
	subj := ParsePublisherRequirement("subject:Lantern Networks, Inc.").Describe()
	if !strings.Contains(subj, "Lantern Networks, Inc.") || !strings.Contains(subj, "before msiexec") {
		t.Fatalf("a subject requirement must name the org and when it is checked, got %q", subj)
	}
	thumb := ParsePublisherRequirement("thumbprint:" + lantern().Thumbprint).Describe()
	if !strings.Contains(thumb, "renewal") {
		t.Fatalf("a thumbprint requirement must warn that a renewal invalidates it, got %q", thumb)
	}
}
