//go:build windows

package blobstore

import (
	"path/filepath"
	"testing"
)

// The cross-process guarantee is NOT made on Windows, and the test that asserts it lives under !windows.
//
// ★ WHY THAT IS A SCOPE AND NOT A GAP. `flock_windows.go` is a deliberate no-op with its reason written down:
// the stores this guards are Edge-side and the Edge runs on Linux. I checked the claim rather than trusting
// it — every importer of this package is on the edge/control-plane side, and no Windows client imports it.
// So the twenty-fourth review's test, which has no build tag, runs here and fails on a promise this platform
// never made:
//
//	the store could not be parsed (unexpected end of JSON input): another process was writing it at the
//	same time, through the same temporary file
//
// Keeping it shared would pin the absence of the lock as a defect on a platform where the code says, in as
// many words, that it is not one. Deleting it would lose the property where it IS provided. So it is scoped,
// and what this platform owes is asserted instead.
//
// ★ AND THE DAY THIS MOVES, IT MOVES HERE. If a Windows component ever imports blobstore, the no-op stops
// being a scope and becomes the lost-update defect the Unix lock exists to prevent — LockFileEx is the
// equivalent, and `flock_windows.go` says so at the place someone would look.

// withFileLock is a pass-through here: it must still RUN the work, or every store on this platform would be
// silently read-only.
func TestTheFileLockIsAPassThroughRatherThanAFailure(t *testing.T) {
	ran := false
	err := withFileLock(filepath.Join(t.TempDir(), "store.json"), func() error {
		ran = true
		return nil
	})
	if err != nil {
		t.Fatalf("withFileLock returned %v — on Windows it has no lock to take, so it must not be the thing that "+
			"fails a write", err)
	}
	if !ran {
		t.Fatal("the work was not run: a no-op lock that also skips the operation would make every store on this " +
			"platform silently do nothing")
	}
}

// And an error from the work reaches the caller: swallowing it would turn a failed save into a successful one,
// which is worse than the missing lock.
func TestThePassThroughDoesNotSwallowTheWorksError(t *testing.T) {
	want := errForTest{}
	if got := withFileLock(filepath.Join(t.TempDir(), "store.json"), func() error { return want }); got != error(want) {
		t.Fatalf("withFileLock returned %v, want the work's own error", got)
	}
}

type errForTest struct{}

func (errForTest) Error() string { return "the work failed" }
