package agentpolicy

import (
	"strings"
	"testing"
)

// ★ The verdict table already pins WHICH answer applies. This pins the third answer's WORDS, because for
// keyModeUnverifiable the sentence is the entire deliverable: nothing else happens. A note that drifted into
// "the key looks fine" would still be a keyModeUnverifiable verdict and would still pass every assertion in
// a_key_whose_mode_says_nothing_test.go, while telling the operator the opposite of the truth.
func TestTheUnverifiableNoteCannotBeMistakenForAPass(t *testing.T) {
	note := unverifiableKeyModeNote(`C:\ProgramData\DSSE\agent-policy-signing.key`)

	// It has to say nobody looked. Without this, silence and "checked and fine" read identically.
	if !strings.Contains(note, "NOT checked") {
		t.Errorf("the note does not say the check did not happen: %s", note)
	}
	// It has to name what DOES govern access there, or the operator has nothing to go and verify.
	if !strings.Contains(note, "ACL") {
		t.Errorf("the note does not name what governs access on this platform: %s", note)
	}
	// And the path, because "a key somewhere" is not something anyone can act on.
	if !strings.Contains(note, `agent-policy-signing.key`) {
		t.Errorf("the note does not name the file: %s", note)
	}
}

// ★★★ AND IT MUST NOT NAME A REMEDY THE PLATFORM DOES NOT HAVE. The old message refused to start and told the
// operator to chmod a file on an operating system with no chmod. A message that names an impossible remedy
// reads as a broken product, and the person who cannot act on this one learns to skip the next one.
func TestTheUnverifiableNoteDoesNotTellThemToChmod(t *testing.T) {
	if note := unverifiableKeyModeNote("k"); strings.Contains(note, "chmod") {
		t.Errorf("it still names a remedy that does not exist on the platform this note is for: %s", note)
	}
}
