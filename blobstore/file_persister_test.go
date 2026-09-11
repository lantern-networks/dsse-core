package blobstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// The ordinary case: replace atomically, report nothing special.
func TestFilePersisterSavesAtomicallyWhenItCan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	f := FilePersister{Path: path}
	if err := f.Save([]byte(`{"a":1}`)); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := f.Save([]byte(`{"a":2}`)); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := f.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != `{"a":2}` {
		t.Fatalf("stored %q, want the second write", got)
	}
	// The temp file must not survive; a stale copy of the state beside the live one is its own trap.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("the temp file was left behind")
	}
}

// The case that had been failing silently in production.
//
// A rename cannot replace a path the kernel is holding — a file bind-mounted into a container is the everyday
// example, and mounting a single config file rather than its directory is an ordinary thing to do. Every write
// then failed forever, with one log line per attempt and nothing else. The reference control plane mounted its
// enrolled inventory that way, so the admission ledger for the entire fleet had never once persisted: the file
// was months old while the process reported every change as applied.
//
// The rename cannot be reproduced portably here, so the failure is injected by making the destination
// unrenameable-onto in the way that matters: what the caller must observe is that the data IS written and that
// the weaker guarantee is REPORTED rather than swallowed.
func TestFilePersisterFallsBackToWritingInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Refuse the rename the way a bind-mounted destination does, leaving everything else writable.
	original := writeFile
	writeFile = func(string, []byte, os.FileMode) error { return syscall.EBUSY }
	t.Cleanup(func() { writeFile = original })

	err := FilePersister{Path: path}.Save([]byte(`{"a":2}`))
	if !errors.Is(err, ErrSavedWithoutAtomicity) {
		t.Fatalf("save reported %v — data that IS written must not be reported as lost", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read back: %v", rerr)
	}
	if string(got) != `{"a":2}` {
		t.Fatalf("stored %q — the fallback did not actually write the data", got)
	}
	// The temp file must not be left behind holding a copy of the same state.
	if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("the temp file survived the fallback")
	}
}

// Saved-without-atomicity must be distinguishable from a real failure. A caller that treats them alike either
// tells an operator their change was lost when it was written, or hides that an interrupted write could
// truncate it — opposite mistakes, both from one comparison.
func TestSavedWithoutAtomicityIsNotAFailure(t *testing.T) {
	if errors.Is(ErrSavedWithoutAtomicity, os.ErrPermission) {
		t.Fatalf("the sentinel must not match unrelated errors")
	}
	if !errors.Is(ErrSavedWithoutAtomicity, ErrSavedWithoutAtomicity) {
		t.Fatalf("the sentinel must be matchable by errors.Is")
	}
}

// ★★ A REPLACEMENT THAT HAPPENED MUST NOT BE "REPAIRED" (2026-08-13, thirtieth review #14). The fallback was
// written against os.Rename, whose error means the destination was untouched. durablefile.Replace is rename
// THEN fsync on this platform, so it can fail with the new file already in place — and the recovery then
// reopened the LIVE store with O_TRUNC and rewrote it. That is a torn window over the file holding spent
// enrolment markers and revocations, on the main path.
func TestAReplacementThatSucceededIsNotRewrittenByTheFallback(t *testing.T) {
	dir := t.TempDir()
	f := &FilePersister{Path: filepath.Join(dir, "admission.json")}
	if err := f.Save([]byte(`{"spent":["tok_1"]}`)); err != nil {
		t.Fatal(err)
	}

	// The shape the shared package reports when the rename went through and the directory fsync did not: the
	// destination IS updated, and only its durability is in doubt.
	original := writeFile
	writeFile = func(path string, data []byte, perm os.FileMode) error {
		if err := os.WriteFile(path, data, perm); err != nil {
			return err
		}
		return fmt.Errorf("%w: injected", durablefile.ErrReplacedNotFlushed)
	}
	defer func() { writeFile = original }()

	err := f.Save([]byte(`{"spent":["tok_1","tok_2"]}`))
	if !errors.Is(err, ErrSavedWithoutAtomicity) {
		t.Fatalf("want the weaker-promise sentinel, got %v", err)
	}
	got, rerr := os.ReadFile(f.Path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != `{"spent":["tok_1","tok_2"]}` {
		t.Fatalf("the store holds %q — the fallback rewrote a file that had already been replaced", got)
	}
	// And no temp file is left beside the live one, which would read as a half-finished write to anyone looking.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("left %q beside the store", e.Name())
		}
	}
}

// ★★ A STAGING FAILURE MUST NOT TRIGGER THE WRITE-THROUGH RECOVERY (2026-08-13, thirty-first review #3). The
// fallback exists for a destination that cannot be REPLACED — a bind-mounted file. The previous round sent
// every non-flush error down it, including "the temporary file could not be written", where the destination is
// untouched and there is nothing to recover. On a full disk the truncate succeeds and the rewrite does not, so
// the store holding spent enrolment markers and revocations ends up empty: the corruption the previous round
// removed, reappearing through the neighbouring error class.
func TestAStagingFailureLeavesTheStoreAloneRatherThanTruncatingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission.json")
	if err := os.WriteFile(path, []byte(`{"spent":["tok_1"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	original := writeFile
	writeFile = func(string, []byte, os.FileMode) error {
		return fmt.Errorf("%w: write /tmp/x: no space left on device", durablefile.ErrStagingFailed)
	}
	t.Cleanup(func() { writeFile = original })

	err := FilePersister{Path: path}.Save([]byte(`{"spent":["tok_1","tok_2"]}`))
	if err == nil {
		t.Fatal("a staging failure reported success")
	}
	if errors.Is(err, ErrSavedWithoutAtomicity) {
		t.Fatal("a staging failure was reported as SAVED — nothing was written")
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != `{"spent":["tok_1"]}` {
		t.Fatalf("the store now holds %q — the recovery truncated a file that was never in danger", got)
	}
}
