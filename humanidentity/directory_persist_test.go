package humanidentity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// The human identity directory was in-memory only. It is populated by IMPORT RUNS (and single upserts) at
// runtime and is never re-seeded, so an Edge restart erased every identity — and every identity-scoped decision
// lost its subject until the next import happened to land. These tests pin the durability that removes that
// failure mode. See docs/edge_state_durability_design.md.

func newPersistedDirectory(t *testing.T, path string) *HumanIdentityDirectoryStore {
	t.Helper()
	store := NewHumanIdentityDirectoryStore()
	if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	return store
}

// THE REGRESSION: an IMPORT RUN must outlive the process that recorded it. Import is the primary way the
// directory is populated, and it writes through the per-item Upsert path, so this is the case that actually
// broke a reference Edge on restart.
func TestImportRunSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "human_identity_directory.json")
	ctx := context.Background()
	now := time.Now().UTC()

	s1 := newPersistedDirectory(t, path)
	req := HumanIdentityDirectoryImportRequest{
		Source:      "okta",
		ImportRunID: "run_001",
		Identities: []model.HumanIdentity{
			{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"},
			{ID: "u2", TenantID: "acme", Subject: "bob@acme.example"},
		},
	}
	if _, err := HumanIdentityDirectoryImport(ctx, s1, req, "acme", now); err != nil {
		t.Fatalf("import: %v", err)
	}

	// A fresh Edge process reading the same store = the restart.
	s2 := newPersistedDirectory(t, path)
	users, err := s2.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("imported directory was LOST across the restart: got %d identities, want 2", len(users))
	}
}

// A single Upsert must also survive.
func TestUpsertSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "human_identity_directory.json")
	ctx := context.Background()
	now := time.Now().UTC()

	s1 := newPersistedDirectory(t, path)
	if _, err := s1.Upsert(ctx, model.HumanIdentity{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"}, "acme", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	s2 := newPersistedDirectory(t, path)
	users, err := s2.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 1 || users[0].ID != "u1" {
		t.Fatalf("upsert was LOST across the restart: %#v", users)
	}

	// Source policies must survive too — a restart that dropped them would silently re-enable a disabled source.
	if _, err := s1.UpsertSourcePolicy(ctx, HumanIdentitySourcePolicy{TenantID: "acme", Source: "okta", Enabled: false}); err != nil {
		t.Fatalf("UpsertSourcePolicy: %v", err)
	}
	s3 := newPersistedDirectory(t, path)
	policies, err := s3.ListSourcePolicies(ctx, "acme")
	if err != nil {
		t.Fatalf("ListSourcePolicies: %v", err)
	}
	if len(policies) != 1 || policies[0].Enabled {
		t.Fatalf("source policy was LOST or re-enabled across the restart: %#v", policies)
	}
}

// A reconcile that DELETES an identity must not come back from the dead on the next restart.
func TestDeletionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "human_identity_directory.json")
	ctx := context.Background()
	now := time.Now().UTC()

	s1 := newPersistedDirectory(t, path)
	// First import seeds two identities from the source.
	if _, err := HumanIdentityDirectoryImport(ctx, s1, HumanIdentityDirectoryImportRequest{
		Source:      "okta",
		ImportRunID: "run_001",
		Identities: []model.HumanIdentity{
			{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"},
			{ID: "u2", TenantID: "acme", Subject: "bob@acme.example"},
		},
	}, "acme", now); err != nil {
		t.Fatalf("seed import: %v", err)
	}
	// Second import with reconcile drops u2 (it is no longer present in the source).
	reconcile := true
	if _, err := HumanIdentityDirectoryImport(ctx, s1, HumanIdentityDirectoryImportRequest{
		Source:           "okta",
		ImportRunID:      "run_002",
		ReconcileMissing: &reconcile,
		Identities: []model.HumanIdentity{
			{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"},
		},
	}, "acme", now.Add(time.Minute)); err != nil {
		t.Fatalf("reconcile import: %v", err)
	}

	s2 := newPersistedDirectory(t, path)
	active, err := s2.List(ctx, "acme", HumanIdentityDirectoryListOptions{Status: "active"})
	if err != nil {
		t.Fatalf("List active: %v", err)
	}
	if len(active) != 1 || active[0].ID != "u1" {
		t.Fatalf("reconcile deletion did not survive the restart: active = %#v", active)
	}
}

// A save failure must be REPORTED, never swallowed. If it is dropped the mutation still returns success and the
// Console still shows the directory, so the operator believes it is durable — and it is gone at the next restart.
type failingPersister struct{ err error }

func (f failingPersister) Load() ([]byte, error) { return nil, nil }
func (f failingPersister) Save([]byte) error     { return f.err }

func TestPersistErrorIsReportedNotSwallowed(t *testing.T) {
	prev := OnPersistError
	t.Cleanup(func() { OnPersistError = prev })
	var got error
	OnPersistError = func(err error) { got = err }

	ctx := context.Background()
	s := NewHumanIdentityDirectoryStore()
	if err := s.SetPersister(failingPersister{err: errTestDiskFull}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if _, err := s.Upsert(ctx, model.HumanIdentity{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"}, "acme", time.Now()); !errors.Is(err, ErrDirectoryPersistence) {
		t.Fatalf("Upsert error = %v, want persistence failure", err)
	}
	if got == nil {
		t.Fatal("a failed save was swallowed; the operator would believe the directory is durable when it is not")
	}
	// A rejected save must neither publish the identity nor advance the bundle version.
	users, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 0 || s.ConfigGeneration() != 0 {
		t.Fatalf("rejected mutation was published: identities=%#v generation=%d", users, s.ConfigGeneration())
	}
}

// Persistence is opt-in: without a persister nothing is written and the old behaviour is unchanged.
func TestNoPersisterKeepsInMemoryBehaviour(t *testing.T) {
	ctx := context.Background()
	s := NewHumanIdentityDirectoryStore()
	if _, err := s.Upsert(ctx, model.HumanIdentity{ID: "u1", TenantID: "acme", Subject: "alice@acme.example"}, "acme", time.Now()); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	users, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 1 {
		t.Fatal("in-memory directory must still work without a persister")
	}
}

var errTestDiskFull = errors.New("disk full")
