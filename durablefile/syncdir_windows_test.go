//go:build windows

package durablefile

import (
	"path/filepath"
	"testing"
)

// The POSIX assertion — "a directory that cannot be fsynced must report it" — does not transfer, and pinning
// it here would pin the break rather than the behaviour.
//
// There is no user-mode API on this platform that flushes a directory: FlushFileBuffers is defined for file
// and volume handles, and issuing it against a directory handle is answered with ERROR_ACCESS_DENIED. The
// portable implementation did exactly that, reported the error faithfully, and so failed EVERY write on
// Windows. What the fsync buys elsewhere comes from the rename instead — MoveFileEx with WRITE_THROUGH.
//
// So the contract this platform owes is the one below: the no-op is deliberate and never itself the reason a
// write fails.
//
// Moved here from agentupdate/journal_dirsync_windows_test.go when the journal stopped carrying its own copy
// of this code (2026-08-13, thirtieth review #20).
func TestTheDirectorySyncIsADeliberateNoOpHere(t *testing.T) {
	if err := SyncDir(filepath.Join(t.TempDir(), "not-there")); err != nil {
		t.Fatalf("SyncDir returned %v — on Windows it must not be the thing that fails a write, because there is "+
			"no directory flush to attempt and the replace carries the durability instead", err)
	}
}
