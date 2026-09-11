package agentupdate

import "testing"

// ★★ THE RULE, TESTED ONCE (2026-08-14, thirty-first review #11). It used to be spelled out in both platforms'
// tick loops as verbatim twins, which meant it was TESTED twice too — or, as actually happened, agreed for both
// and shipped on one. These cases are the whole rule; a platform now gets them by calling, not by copying.
func TestStagedClears(t *testing.T) {
	poisoned := &Journal{TargetVersion: "0.2.1", Phase: PhaseFailed, Poisoned: map[string]string{"0.2.1": "withdrawn"}}

	for _, tc := range []struct {
		name   string
		j      *Journal
		dry    bool
		want   []StagedClear
		reason string
	}{
		{
			name: "an installed version is finished with",
			j:    &Journal{TargetVersion: "0.2.1", Phase: PhaseCompleted},
			want: []StagedClear{{Version: "0.2.1", Reason: StagedClearInstalled}},
		},
		{
			name:   "a failed attempt KEEPS its bytes",
			j:      &Journal{TargetVersion: "0.2.1", Phase: PhaseFailed},
			want:   nil,
			reason: "the next window must retry without re-downloading tens of megabytes",
		},
		{
			name:   "a version this device will never install is finished with",
			j:      poisoned,
			want:   []StagedClear{{Version: "0.2.1", Reason: StagedClearRefused}},
			reason: "left alone these accumulate: one privileged installer per release the fleet changed its mind about",
		},
		{
			name:   "a dry run deletes nothing",
			j:      &Journal{TargetVersion: "0.2.1", Phase: PhaseCompleted},
			dry:    true,
			want:   nil,
			reason: "--dry-run exists to SAY what would happen, and deleting a file is not saying",
		},
		{
			name: "an in-flight attempt is not touched",
			j:    &Journal{TargetVersion: "0.2.1", Phase: PhaseVerified},
			want: nil,
		},
		{
			name: "no journal, nothing to clear",
			j:    nil,
			want: nil,
		},
		{
			name:   "a completed attempt with no target names nothing",
			j:      &Journal{Phase: PhaseCompleted},
			want:   nil,
			reason: "a clear keyed by an empty version would ask the platform to delete a path built from nothing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StagedClears(tc.j, tc.dry)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v — %s", got, tc.want, tc.reason)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v — %s", got[i], tc.want[i], tc.reason)
				}
			}
		})
	}
}

// ★ COMPLETED OUTRANKS POISONED. A version that installed and was LATER poisoned is still installed, and the
// note an operator reads must not call it "refused" — the bytes are gone either way, but the reason is the
// record of what happened on this device.
func TestAnInstalledVersionThatWasLaterPoisonedReadsAsInstalled(t *testing.T) {
	j := &Journal{TargetVersion: "0.2.1", Phase: PhaseCompleted, Poisoned: map[string]string{"0.2.1": "withdrawn"}}
	got := StagedClears(j, false)
	if len(got) != 1 || got[0].Reason != StagedClearInstalled {
		t.Fatalf("got %v, want one clear reading as installed", got)
	}
}

// The note has to say what to do about it: best-effort is the rule everywhere, so this text is the ONLY
// consequence of a failed removal.
func TestTheFailureNoteNamesTheVersionAndWhatToDo(t *testing.T) {
	n := StagedClearNote(StagedClear{Version: "0.2.1", Reason: StagedClearInstalled}, errTest{})
	for _, want := range []string{"0.2.1", "privileged install", "by hand"} {
		if !contains(n, want) {
			t.Fatalf("the note does not mention %q: %s", want, n)
		}
	}
	r := StagedClearNote(StagedClear{Version: "0.2.1", Reason: StagedClearRefused}, errTest{})
	if !contains(r, "refused") {
		t.Fatalf("a refused version's note does not say so: %s", r)
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
