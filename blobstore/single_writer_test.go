package blobstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ★ TWO EDGES SHARED ONE LEDGER FILE (2026-08-12, twenty-third review). Whoever saved last won, so an
// enrolment recorded by one node was erased by another applying a config bundle from an older snapshot — and
// the identity could then be enrolled a second time.

func TestASaveThatWouldEraseAnotherWritersChangeIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	a := NewSingleWriterFilePersister(FilePersister{Path: path})
	if err := a.Save([]byte(`{"entries":{"a-1":{"device_enrolled_at":"now"}}}`)); err != nil {
		t.Fatal(err)
	}

	// Another process — its own snapshot, its own write.
	b := NewSingleWriterFilePersister(FilePersister{Path: path})
	if _, err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if err := a.Save([]byte(`{"entries":{"a-1":{"device_enrolled_at":"later"}}}`)); err != nil {
		t.Fatal(err)
	}

	// b now writes what it decided BEFORE a's second save. That is the lost update.
	err := b.Save([]byte(`{"entries":{"a-1":{}}}`))

	if !errors.Is(err, ErrConcurrentWriter) {
		t.Fatalf("a stale writer was allowed to overwrite the store (err=%v) — on the real deployment that is "+
			"an enrolment record erased, and the identity can be enrolled again", err)
	}
	// And the bytes on disk are still the ones that were not erased.
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(raw) != `{"entries":{"a-1":{"device_enrolled_at":"later"}}}` {
		t.Fatalf("the refused save wrote anyway: %s", raw)
	}
}

// The ordinary case: one writer, many saves, no complaints.
func TestASingleWriterSavesRepeatedly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	p := NewSingleWriterFilePersister(FilePersister{Path: path})
	for i := 0; i < 5; i++ {
		if err := p.Save([]byte(`{"n":` + string(rune('0'+i)) + `}`)); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if _, err := p.Load(); err != nil {
		t.Fatal(err)
	}
	if err := p.Save([]byte(`{"n":9}`)); err != nil {
		t.Fatalf("a save after this writer's own load was refused: %v", err)
	}
}

// A store that does not exist yet is not "somebody else's".
func TestAFirstSaveIntoAnEmptyDirectoryIsAllowed(t *testing.T) {
	p := NewSingleWriterFilePersister(FilePersister{Path: filepath.Join(t.TempDir(), "new.json")})
	if err := p.Save([]byte(`{}`)); err != nil {
		t.Fatalf("the first save was refused: %v", err)
	}
}
