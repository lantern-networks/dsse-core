package main

import (
	"path/filepath"
	"testing"
)

// ★ AN ANNOUNCEMENT REORDERED IS NOT AN ANNOUNCEMENT CHANGED (2026-08-20). Two nodes in one fleet share this
// store; if the comparison is order-sensitive, each reads the other's write as a change, the serial climbs
// forever with nothing changing, and every advance throws away the adoption evidence below it — which is what
// the promotion gate for roadmap D reads.
func TestReorderingTheAnnouncementIsNotAChange(t *testing.T) {
	store := &transportTrustStore{
		announced: canonicalAnnouncement("b=2,a=1,c=3"), path: filepath.Join(t.TempDir(), "trust.json"), serial: 7,
		resign: func(string, int64) (func(), error) { return func() {}, nil },
	}
	if _, moved, err := store.AdvanceForAnnouncement([]string{"a=1", "b=2", "c=3"}, "test"); err != nil || moved {
		t.Fatalf("the same set in another order advanced the serial (moved=%v err=%v)", moved, err)
	}
	if _, moved, err := store.AdvanceForAnnouncement([]string{"a=1", "b=2"}, "test"); err != nil || !moved {
		t.Fatalf("a genuine change did not advance (moved=%v err=%v)", moved, err)
	}
}

// And the value a previous build persisted is read the same way, so upgrading does not advance the serial on
// every node for nothing.
func TestAnAnnouncementWrittenInAnotherOrderReadsTheSame(t *testing.T) {
	if canonicalAnnouncement("b=2,a=1,c=3") != canonicalAnnouncement("a=1,c=3,b=2") {
		t.Fatal("the same set written in two orders is not read as the same announcement")
	}
	if canonicalAnnouncement("a=1,b=2") == canonicalAnnouncement("a=1,b=2,c=3") {
		t.Fatal("a genuine difference was canonicalised away")
	}
}
