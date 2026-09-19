package nhi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
	if _, err := s.Upsert(ctx, testIdentity("nhi_x"), "tenant_a", time.Now()); !errors.Is(err, ErrPersistence) {
		t.Fatalf("upsert: %v", err)
	}
	if got == nil {
		t.Fatal("a failed save was swallowed; the operator would believe the NHI is durable when it is not")
	}
	// A rejected durable write must not publish the account or advance configuration.
	items, err := s.List(ctx, "tenant_a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 0 || s.ConfigGeneration() != 0 {
		t.Fatalf("rejected mutation became visible: %#v", items)
	}
}

var errTestDiskFull = errors.New("disk full")

type gatedRegistryPersister struct {
	blobstore.FilePersister
	fail bool
}

func (p *gatedRegistryPersister) Save(data []byte) error {
	if p.fail {
		return errTestDiskFull
	}
	return p.FilePersister.Save(data)
}

func TestRejectedAccountNeverReappearsAfterAnotherSave(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	p := &gatedRegistryPersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "accounts.json")}}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	original, err := s.Upsert(ctx, testIdentity("existing"), "tenant_a", now)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	generation := s.ConfigGeneration()
	p.fail = true
	for _, id := range []string{"existing", "rejected"} {
		item := testIdentity(id)
		item.Status = "suspended"
		if _, err := s.Upsert(ctx, item, "tenant_a", now); !errors.Is(err, ErrPersistence) {
			t.Fatal(err)
		}
	}
	items, _ := s.List(ctx, "tenant_a")
	after, _ := p.Load()
	if len(items) != 1 || items[0].Status != original.Status || s.ConfigGeneration() != generation || string(before) != string(after) {
		t.Fatalf("failed write published: %+v", items)
	}
	p.fail = false
	if _, err := s.Upsert(ctx, testIdentity("accepted"), "tenant_a", now); err != nil {
		t.Fatal(err)
	}
	restarted := newPersistedStore(t, p.Path)
	items, _ = restarted.List(ctx, "tenant_a")
	if len(items) != 2 || items[1].ID != "existing" || items[1].Status != "active" {
		t.Fatalf("rejected candidate reappeared: %+v", items)
	}
}

func TestLegacyAccountsReindexAndKeepSameIDInTwoTenants(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	path := filepath.Join(t.TempDir(), "accounts.json")
	legacy := testIdentity("shared")
	data, _ := json.Marshal(registryPersistSnapshot{Identities: map[string]model.NonHumanIdentity{"shared": legacy}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := newPersistedStore(t, path)
	other := testIdentity("shared")
	other.TenantID = "tenant_b"
	other.Name = "Other tenant"
	if _, err := s.Upsert(ctx, other, "tenant_b", now); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkUsed(ctx, "tenant_b", "shared", now); err != nil || !ok {
		t.Fatalf("mark used: %v %v", ok, err)
	}
	for _, source := range []*Store{s, newPersistedStore(t, path)} {
		a, _ := source.List(ctx, "tenant_a")
		b, _ := source.List(ctx, "tenant_b")
		if len(a) != 1 || len(b) != 1 || a[0].Name != legacy.Name || a[0].LastUsedAt != nil || b[0].Name != other.Name || b[0].LastUsedAt == nil {
			t.Fatalf("tenant collision: %+v %+v", a, b)
		}
	}
}

func TestAccountNamespaceRejectsAmbiguousKeys(t *testing.T) {
	for _, tc := range []struct{ tenant, id string }{{"tenant_a", "x\x00y"}, {"tenant\x00a", "x"}} {
		item := testIdentity(tc.id)
		item.TenantID = tc.tenant
		if _, err := NewStore().Upsert(context.Background(), item, tc.tenant, time.Now()); err == nil {
			t.Fatal("NUL key accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "accounts.json")
	data, _ := json.Marshal(registryPersistSnapshot{Identities: map[string]model.NonHumanIdentity{"one": testIdentity("same"), "two": testIdentity("same")}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(testIdentity("keep"))
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err == nil {
		t.Fatal("ambiguous saved records accepted")
	}
	items, _ := s.List(context.Background(), "tenant_a")
	if len(items) != 1 || items[0].ID != "keep" {
		t.Fatalf("load changed memory on error: %+v", items)
	}
}
