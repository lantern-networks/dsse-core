package agentupdate

import (
	"path/filepath"
	"testing"
	"time"
)

// journal_dir_sync_test.go — the rename that makes the journal the journal is a directory write, and Save has
// to persist it.
//
// ★ THE FILE WAS DURABLE AND THE RENAME WAS NOT (2026-08-12, fourteenth review). fsync on the temp file
// persists contents; the directory entry is separate, and a power cut between them leaves the PREVIOUS
// journal. Everything this file exists for lives in that gap — an interrupted install reads as never
// attempted, an owed outcome is not owed, and the accepted plan floor moves backwards, which is the one
// direction a replay defence must never move.
//
// HOW the rename is persisted is per-platform and so are the assertions about it: see
// journal_dirsync_unix_test.go and journal_dirsync_windows_test.go. What belongs here is the property both
// platforms owe the caller.

// The ordinary path still works — a Save that reports an error nobody can act on is its own failure.
//
// ★ AND THIS IS THE TEST THAT CAUGHT THE BREAK. The portable syncDir made every Save on Windows fail with
// "Access is denied", so an agent on that platform could not record an attempt, an outcome, or the plan floor.
// It reads like a formality and it is the one that fired.
func TestAnOrdinarySaveStillSucceeds(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	path := filepath.Join(t.TempDir(), "nested", "journal.json")
	if err := j.Save(path); err != nil {
		t.Fatalf("saving a journal into a directory that has to be created failed: %v", err)
	}
	if _, err := LoadJournal(path); err != nil {
		t.Fatalf("the journal did not read back: %v", err)
	}
}
