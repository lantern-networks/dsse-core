package eastwestobserve

import (
	"fmt"
	"testing"
	"time"
)

// flakyPersister fails the first N saves, then succeeds — the transient-outage case behind review #17.
type flakyPersister struct {
	failuresLeft int
	saved        [][]byte
}

func (p *flakyPersister) Load() ([]byte, error) { return nil, nil }
func (p *flakyPersister) Save(data []byte) error {
	if p.failuresLeft > 0 {
		p.failuresLeft--
		return fmt.Errorf("transient outage")
	}
	p.saved = append(p.saved, data)
	return nil
}

// Review #17: PersistIfDirty cleared the dirty flag BEFORE Save ran, so a transient Save failure silently
// dropped the snapshot — the next periodic flush saw a "clean" store and did nothing until some future
// Observe happened to re-dirty it. A failed Save must leave the store dirty so the next flush retries.
func TestPersistIfDirtyRetriesAfterFailedSave(t *testing.T) {
	s := NewStore()
	p := &flakyPersister{failuresLeft: 1}
	if err := s.SetPersister(p, 0); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s.Observe("t1", "dev1", "", "10.0.0.5", "ssh", 22, time.Now())

	if err := s.PersistIfDirty(); err == nil {
		t.Fatal("first flush should surface the Save failure")
	}
	// No new Observe happened — the retry must come purely from the store staying dirty.
	if err := s.PersistIfDirty(); err != nil {
		t.Fatalf("second flush should succeed, got %v", err)
	}
	if len(p.saved) != 1 {
		t.Fatalf("expected exactly one successful snapshot, got %d", len(p.saved))
	}
	// Now clean: a further flush is a no-op.
	if err := s.PersistIfDirty(); err != nil || len(p.saved) != 1 {
		t.Fatalf("clean store must not re-save, err=%v saves=%d", err, len(p.saved))
	}
}
