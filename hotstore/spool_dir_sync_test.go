package hotstore

import (
	"os"
	"path/filepath"
	"testing"
)

// spool_dir_sync_test.go — the directory half of "fsync the file AND its directory" has to be reported when it
// fails, or the comment is the only place the durability exists.
//
// ★ IT WAS DISCARDED (2026-08-12, fourteenth review): open, Sync and Close on the directory all went to `_`.
// The function had been rewritten one review earlier precisely to stop making a durability claim the
// deployment does not provide, and it went on making half of it.

func TestASpoolDirectoryThatCannotBeSyncedIsReported(t *testing.T) {
	dir := t.TempDir()
	// A spool whose PARENT is a file: MkdirAll fails, and the failure must reach the caller rather than be
	// swallowed on the way to a successful-looking return.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &BatchIngestor{spoolPath: filepath.Join(blocker, "spool", "backlog.json")}

	err := b.spoolBacklog([][]IngestRecord{{{Stream: "s", Row: map[string]any{"event_id": "e"}}}})

	if err == nil {
		t.Fatal("a spool that could not be created returned no error: the deployment believes it has a durable " +
			"spool and has none, which is the exact shape this function was rewritten to stop producing")
	}
}

// Removing the spool when the backlog drains is a directory write too, and it must succeed rather than be
// reported as a failure — an empty backlog is the normal case, not an error.
func TestDrainingTheBacklogClearsTheSpoolWithoutComplaint(t *testing.T) {
	dir := t.TempDir()
	b := &BatchIngestor{spoolPath: filepath.Join(dir, "backlog.json")}
	if err := b.spoolBacklog([][]IngestRecord{{{Stream: "s", Row: map[string]any{"event_id": "e"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.spoolPath); err != nil {
		t.Fatalf("the spool was not written: %v", err)
	}

	if err := b.spoolBacklog(nil); err != nil {
		t.Fatalf("clearing a drained backlog reported an error: %v", err)
	}
	if _, err := os.Stat(b.spoolPath); !os.IsNotExist(err) {
		t.Fatal("the spool survived a drained backlog; a restart would re-ingest rows the hot store already has")
	}
}

// The "a directory that cannot be fsynced says so" assertion is a POSIX property and lives in
// spool_dirsync_unix_test.go; Windows has no directory flush to attempt and its counterpart is beside it.
// Both tests above are platform-neutral and stay here: they assert what the SPOOL owes, not how a rename is
// persisted.
