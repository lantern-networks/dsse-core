package eastwestobserve

import (
	"testing"
	"time"
)

func TestOutOfOrderObservationSurvivesRestart(t *testing.T) {
	p := &memPersister{}
	s := NewStore()
	if err := s.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	newer := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Minute)
	s.Observe("tenant", "device", "new-user", "db.example", "ssh", 22, newer)
	got := s.Observe("tenant", "device", "old-user", "db.example", "ssh", 22, older)
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	restarted := NewStore()
	if err := restarted.SetPersister(p, 0); err != nil {
		t.Fatalf("out-of-order observation made saved inventory unreadable: %v", err)
	}
	if got.Count != 2 || got.FirstSeen != older.Format(time.RFC3339) || got.LastSeen != newer.Format(time.RFC3339) || got.User != "new-user" {
		t.Fatalf("observation lost chronological attribution: %+v", got)
	}
	rows := restarted.List("tenant")
	if len(rows) != 1 || rows[0] != got {
		t.Fatal("restart changed observation")
	}
}
