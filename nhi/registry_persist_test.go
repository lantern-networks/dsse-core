package nhi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// The NHI registry was in-memory only. A routine Edge restart therefore wiped every registered non-human
// identity: any decision that validates against the registry then behaves as if the NHI was never registered,
// and nothing recovers it except re-authoring every NHI by hand. These tests pin the durability that removes
// that failure mode. Mirrors connector/registry_persist_test.go.

func testIdentity(id string) model.NonHumanIdentity {
	return model.NonHumanIdentity{
		ID:          id,
		TenantID:    "tenant_a",
		Name:        "CI Runner",
		NHIType:     "automation",
		OwnerUserID: "user_ops",
		Status:      "active",
	}
}

func newPersistedStore(t *testing.T, path string) *Store {
	t.Helper()
	s := NewStore()
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	return s
}

// THE REGRESSION: a registered NHI must outlive the process that recorded it.
func TestUpsertSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nhi_registry.json")
	ctx := context.Background()
	now := time.Now()

	s1 := newPersistedStore(t, path)
	if _, err := s1.Upsert(ctx, testIdentity("nhi_ci_001"), "tenant_a", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// A fresh Edge process reading the same store = the restart.
	s2 := newPersistedStore(t, path)
	items, err := s2.List(ctx, "tenant_a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("NHI was LOST across the restart — the registry went empty: %#v", items)
	}
	if items[0].ID != "nhi_ci_001" || items[0].Name != "CI Runner" || items[0].NHIType != "automation" {
		t.Fatalf("identity restored with wrong content: %+v", items[0])
	}
}

// A MarkUsed mutation (last_used_at) must also survive a restart.
func TestMarkUsedSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nhi_registry.json")
	ctx := context.Background()
	now := time.Now()

	s1 := newPersistedStore(t, path)
	if _, err := s1.Upsert(ctx, testIdentity("nhi_used"), "tenant_a", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	ok, err := s1.MarkUsed(ctx, "tenant_a", "nhi_used", now)
	if err != nil || !ok {
		t.Fatalf("MarkUsed: ok=%v err=%v", ok, err)
	}

	s2 := newPersistedStore(t, path)
	items, err := s2.List(ctx, "tenant_a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 || items[0].LastUsedAt == nil {
		t.Fatalf("last_used_at did not survive the restart: %#v", items)
	}
}

// A save failure must be REPORTED, never swallowed. If it is dropped, the Upsert still returns success and the
// Console still shows the NHI, so the operator believes it is durable — and it is gone at the next restart.
type failingPersister struct{ err error }

func (f failingPersister) Load() ([]byte, error) { return nil, nil }
func (f failingPersister) Save([]byte) error     { return f.err }

func TestPersistErrorIsReportedNotSwallowed(t *testing.T) {
	prev := OnPersistError
	t.Cleanup(func() { OnPersistError = prev })
	var got error
	OnPersistError = func(err error) { got = err }

	ctx := context.Background()
	s := NewStore()
	if err := s.SetPersister(failingPersister{err: errTestDiskFull}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if _, err := s.Upsert(ctx, testIdentity("nhi_x"), "tenant_a", time.Now()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got == nil {
		t.Fatal("a failed save was swallowed; the operator would believe the NHI is durable when it is not")
	}
	// The mutation itself still applies: the in-memory set is serving, and refusing the operator's change
	// because the disk is unhappy is a different and worse failure.
	items, err := s.List(ctx, "tenant_a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("identities = %#v, want the mutation to still apply", items)
	}
}

var errTestDiskFull = errors.New("disk full")
