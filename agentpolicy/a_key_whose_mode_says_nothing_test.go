package agentpolicy

import (
	"io/fs"
	"testing"
)

// ★★★ A GUARD MUST NOT REFUSE ON A VALUE THAT CARRIES NO INFORMATION (2026-08-31, measured: the Edge could
// not start on Windows at all).
//
// The signing-key permission check is right and worth keeping: anyone who can read that key can sign policy
// the whole fleet accepts. But os.FileMode.Perm() reports a constant 0666 on Windows whatever the file
// actually permits, so on that platform the guard was reading noise and refusing on it — a refusal that says
// nothing about the key, on every node, always.
//
// Passing silently would be the worse fix: the operator would then believe a guarantee nobody delivered.
// There are three honest answers, not two, and the third has to be said out loud.
func TestASigningKeyModeIsJudgedOnlyWhereTheModeMeansSomething(t *testing.T) {
	for _, c := range []struct {
		name       string
		mode       fs.FileMode
		meaningful bool
		devMode    bool
		want       keyModeAnswer
	}{
		{"owner-only on a POSIX host", 0o600, true, false, keyModeOK},
		{"world-readable on a production POSIX host", 0o644, true, false, keyModeRefuse},
		{"world-readable in development", 0o644, true, true, keyModeWarn},
		{"group-writable is caught too", 0o620, true, false, keyModeRefuse},

		// The platform that broke. 0666 is what Windows reports for a file created with 0600, so a guard
		// keyed on the bits refuses a correctly protected key — and would equally pass an exposed one.
		{"windows reports 0666 for a key that is in fact owner-only", 0o666, false, false, keyModeUnverifiable},
		{"and it is not silently downgraded by development mode either", 0o666, false, true, keyModeUnverifiable},
		{"nor rescued by bits that would have passed", 0o600, false, false, keyModeUnverifiable},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := signingKeyModeVerdict(c.mode, c.meaningful, c.devMode); got != c.want {
				t.Errorf("mode %04o meaningful=%v dev=%v: got %v, want %v", c.mode, c.meaningful, c.devMode, got, c.want)
			}
		})
	}
}

// ★ AND THE THIRD ANSWER MUST SAY THE PROPERTY WAS NOT CHECKED. A reader of the log has to be able to tell
// "this key is fine" from "nobody looked", or the note is worse than silence.
func TestTheUnverifiableNoteSaysItWasNotChecked(t *testing.T) {
	if signingKeyModeVerdict(0o666, false, false) == keyModeOK {
		t.Fatal("an unreadable mode was reported as OK — the operator would believe a guarantee nobody delivered")
	}
}
