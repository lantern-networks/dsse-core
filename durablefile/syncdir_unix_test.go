//go:build !windows

package durablefile

import (
	"path/filepath"
	"strings"
	"testing"
)

// On these systems the fsync IS the mechanism, so a failure to perform it is a failure to be durable and the
// caller has to hear about it.
//
// Moved here from agentupdate/journal_dirsync_unix_test.go when the journal stopped carrying its own copy of
// this code (2026-08-13, thirtieth review #20). The assertion belongs with the implementation, and leaving it
// behind would have deleted the only test of it.
func TestADirectorySyncFailureIsReportedRatherThanSwallowed(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "not-there"))
	if err == nil {
		t.Fatal("syncing a directory that does not exist returned nil: a write on a filesystem that cannot " +
			"persist the rename would report success and the file would not be durable")
	}
	if !strings.Contains(err.Error(), "persist the rename") {
		t.Fatalf("the error does not say what was not persisted: %v", err)
	}
}
