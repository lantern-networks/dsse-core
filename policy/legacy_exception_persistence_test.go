package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// Legacy exceptions + the server-initiated enable toggle are admin-authored CONFIG and must survive an
// Edge restart (they were in-memory only, lost on restart, needing a manual seed_legacy_exception.sh).
func TestLegacyExceptionsSurviveRestart(t *testing.T) {
	path := t.TempDir() + "/admin_runtime_state.json"

	s1 := NewStore(nil)
	s1.SetRuntimeStatePath(path)
	s1.SetServerInitiatedEnabled("t1", true)
	s1.UpsertLegacyException("t1", model.LegacyException{ID: "ex1"})
	s1.UpsertLegacyException("t1", model.LegacyException{ID: "ex2"})

	// Simulate a restart: a fresh store loads the durable file at the same path.
	s2 := NewStore(nil)
	s2.SetRuntimeStatePath(path)

	exs := s2.LegacyExceptionsFor("t1")
	if len(exs) != 2 || exs[0].ID != "ex1" || exs[1].ID != "ex2" {
		t.Fatalf("legacy exceptions lost on restart: %+v", exs)
	}
	s2.mu.RLock()
	enabled := s2.serverInitiatedEnabled["t1"]
	s2.mu.RUnlock()
	if !enabled {
		t.Fatal("server-initiated enable toggle lost on restart")
	}
}

// TestRemoveLegacyException: an exception is deletable by id, the delete persists across a restart, and a
// missing id returns false.
func TestRemoveLegacyException(t *testing.T) {
	path := t.TempDir() + "/admin_runtime_state.json"
	s1 := NewStore(nil)
	s1.SetRuntimeStatePath(path)
	s1.UpsertLegacyException("t1", model.LegacyException{ID: "ex1"})
	s1.UpsertLegacyException("t1", model.LegacyException{ID: "ex2"})

	if s1.RemoveLegacyException("t1", "nope") {
		t.Fatal("removing an unknown exception should return false")
	}
	if !s1.RemoveLegacyException("t1", "ex1") {
		t.Fatal("removing ex1 should return true")
	}
	if exs := s1.LegacyExceptionsFor("t1"); len(exs) != 1 || exs[0].ID != "ex2" {
		t.Fatalf("after delete want only ex2, got %+v", exs)
	}
	// The removal persists across a restart (ex1 does not come back).
	s2 := NewStore(nil)
	s2.SetRuntimeStatePath(path)
	if exs := s2.LegacyExceptionsFor("t1"); len(exs) != 1 || exs[0].ID != "ex2" {
		t.Fatalf("deleted exception resurrected after restart: %+v", exs)
	}
}
