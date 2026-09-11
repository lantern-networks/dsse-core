package blobstore

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// ★ THE MEASURED FAILURE (2026-08-12, 2026-08-15). Several Edges were given the same bind-mounted state path.
// Once, an enrolment recorded by one node was erased by another saving an older snapshot, so a spent device
// identity could be spent again. Again later, two Edges shared the admin runtime state and config
// distribution silently STOPPED on one of them — it could not save what it applied, so its generation never
// moved — and the only symptom was a node permanently behind, found by comparing generations by hand.
func TestASecondNodeIsRefusedAPathALiveNodeOwns(t *testing.T) {
	path := t.TempDir() + "/enrolled_inventory.json"
	now := time.Now()

	if previous, err := ClaimPath(path, "edge-a", now); err != nil || previous != "" {
		t.Fatalf("first claim: previous=%q err=%v", previous, err)
	}
	_, err := ClaimPath(path, "edge-b", now.Add(time.Minute))
	if !errors.Is(err, ErrPathOwnedByAnotherNode) {
		t.Fatalf("a second node took a live node's path: %v", err)
	}
	if !strings.Contains(err.Error(), "edge-a") || !strings.Contains(err.Error(), path) {
		t.Fatalf("the refusal must name the owner AND the path, got: %v", err)
	}
	// The owner may re-claim its own path — that is a restart, not a conflict.
	if _, err := ClaimPath(path, "edge-a", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("a node restarting lost its own path: %v", err)
	}
}

// A stamp that has stopped being refreshed belongs to a node that is gone. Taking it over is correct, and
// reporting the takeover matters: "this state used to be somewhere else" is the fact that explains an
// incident weeks later.
func TestAStaleStampIsTakenOverAndReported(t *testing.T) {
	path := t.TempDir() + "/admin_runtime_state.json"
	start := time.Now()
	if _, err := ClaimPath(path, "edge-old", start); err != nil {
		t.Fatalf("claim: %v", err)
	}

	previous, err := ClaimPath(path, "edge-new", start.Add(OwnershipStaleAfter+time.Minute))
	if err != nil {
		t.Fatalf("a stale path must be takeable: %v", err)
	}
	if previous != "edge-old" {
		t.Fatalf("previous = %q — the takeover has to name who it took the path from", previous)
	}
}

// Saving refreshes the stamp, so a node that is alive but quiet does not lose its own path. Without this a
// healthy deployment whose config simply is not changing would hand its store to a neighbour after half an
// hour, which is worse than the problem being solved.
func TestSavingKeepsTheStampFresh(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/store.json"
	start := time.Now()
	if _, err := ClaimPath(path, "edge-a", start); err != nil {
		t.Fatalf("claim: %v", err)
	}

	later := start.Add(OwnershipStaleAfter - time.Minute)
	persister := OwnedFilePersister{File: FilePersister{Path: path}, NodeID: "edge-a", Now: func() time.Time { return later }}
	if err := persister.Save([]byte(`{"x":1}`)); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The refreshed stamp means another node is still refused well past the ORIGINAL claim's staleness window.
	if _, err := ClaimPath(path, "edge-b", later.Add(time.Minute)); !errors.Is(err, ErrPathOwnedByAnotherNode) {
		t.Fatalf("a node that saved a minute ago lost its path: %v", err)
	}
	// And the data went where it should.
	if raw, rerr := os.ReadFile(path); rerr != nil || string(raw) != `{"x":1}` {
		t.Fatalf("the wrapper did not write through: %q %v", raw, rerr)
	}
}

// A first boot has no stamp, and a corrupt one is not evidence that somebody else is live: refusing to start
// because a file is unreadable would turn a cosmetic problem into an outage.
func TestNoStampAndCorruptStampBothClaimCleanly(t *testing.T) {
	dir := t.TempDir()
	fresh := dir + "/fresh.json"
	if _, err := ClaimPath(fresh, "edge-a", time.Now()); err != nil {
		t.Fatalf("first boot: %v", err)
	}

	corrupt := dir + "/corrupt.json"
	if err := os.WriteFile(corrupt+".owner", []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ClaimPath(corrupt, "edge-a", time.Now()); err != nil {
		t.Fatalf("a corrupt stamp must not block a claim: %v", err)
	}
}
