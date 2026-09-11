package agentpolicy

// unverifiable_key_mode_note.go — the words of the third answer.
//
// ★ signingKeyModeVerdict decides WHICH of the three answers applies, and its table pins that decision on
// every host. The third answer is different from the other two in one way that matters: for refuse and warn,
// the verdict IS the outcome — a start that fails, a warning that appears. For keyModeUnverifiable nothing
// happens at all except the sentence. The sentence is the entire deliverable.
//
// So it needs its own pinning. An unverifiable verdict whose note quietly drifted into "the key looks fine"
// would satisfy every existing assertion — the verdict is still keyModeUnverifiable — while telling the
// operator the opposite of the truth. And the note is the ONLY thing standing between "nobody checked this"
// and an operator who assumes somebody did.
//
// ★ IT ALSO MUST NOT SAY chmod. That is what made the old Windows message nonsense: it refused, then told the
// operator to run a command their operating system does not have. A message that names an impossible remedy
// reads as a broken product, and the person who cannot act on it learns to skip the next message too.

import (
	"fmt"

	"github.com/lantern-networks/dsse-core/internal/posixperm"
)

// unverifiableKeyModeNote is what is logged when the file mode carries no information on this platform.
func unverifiableKeyModeNote(path string) string {
	return fmt.Sprintf("NOTE: the agent-policy signing key's permissions were NOT checked. %s "+
		"On this platform the key is protected by its ACL, which this guard cannot read: "+
		"confirm %s is readable only by the account this service runs as.",
		posixperm.SkipReason, path)
}
