package durablefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ THE PROPERTY THE CALLERS ARE WRITTEN AGAINST: a reader never sees a partial file, and a failed write does
// not destroy what was there. Both stores using this package treat the file as authority — an update journal
// and a control plane's downgrade floor — so a truncated read is not a retry, it is a wrong decision.
func TestReplacingKeepsTheOldContentsUntilTheNewOnesAreComplete(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "floor.json")

	if err := Write(p, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("got %q err=%v", got, err)
	}

	if err := Write(p, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(p)
	if string(got) != `{"a":2}` {
		t.Fatalf("the replacement did not land: %q", got)
	}

	// No temporary files left behind. They accumulate in a directory an operator reads, and one that looks like
	// the real file is worse than clutter.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "floor.json" {
			t.Fatalf("left behind %q", e.Name())
		}
	}
}

// The mode is set BEFORE the file becomes visible under its real name; otherwise there is a window in which a
// file naming signing authority is readable by anyone. The exact bits are a Unix property — see
// mode_posix_test.go, and mode_windows_test.go for what this same guarantee amounts to on a platform whose
// only permission is a read-only attribute.

// A directory that does not exist is an ERROR, not a silent no-write. The callers create their state directory
// at startup; if it has gone, the honest answer is that the value was not persisted.
func TestWritingIntoAMissingDirectoryFails(t *testing.T) {
	err := Write(filepath.Join(t.TempDir(), "nope", "x.json"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("a write into a missing directory reported success")
	}
	if !strings.Contains(err.Error(), "durablefile:") {
		t.Fatalf("the error should name this package so a caller can tell where it came from: %v", err)
	}
}

// ★ SyncDir MUST BE CALLABLE ON EVERY PLATFORM AND MUST NOT LIE. On Windows it does nothing and says so in a
// comment; the test exists so that "does nothing" stays a decision rather than becoming a mystery.
func TestSyncDirIsCallableOnThisPlatform(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir on a real directory failed: %v", err)
	}
}
