package assetcatalog

import (
	"errors"
	"sync"
	"testing"
)

// The product's Postgres blob has the same serialized Update capability.
type sharedApplicationBlob struct {
	mu  sync.Mutex
	raw []byte
}

type refusedSharedApplicationBlob struct{ sharedApplicationBlob }

func (b *refusedSharedApplicationBlob) Update(func([]byte) ([]byte, error)) error {
	return errors.New("private backend connection detail")
}

func TestSharedCatalogRefusalDoesNotReportSuccessOrExposeBackendDetail(t *testing.T) {
	blob := &refusedSharedApplicationBlob{}
	store := NewStore()
	if err := store.SetPersister(blob); err != nil {
		t.Fatal(err)
	}
	_, err := store.UpsertApplicationEndpoint("wiki", Endpoint{TenantID: "one", Alias: "wiki", Kind: KindNetwork, Address: "wiki.example.test"}, false)
	if !errors.Is(err, ErrSharedUpdateUnconfirmed) || err.Error() != ErrSharedUpdateUnconfirmed.Error() {
		t.Fatalf("write refusal exposed backend detail or was mistaken for success: %v", err)
	}
	if _, found := store.GetEndpoint("one", "app-wiki"); found || store.ConfigGeneration() != 0 {
		t.Fatal("refused shared write changed live catalog")
	}
}

func (b *sharedApplicationBlob) Load() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.raw...), nil
}
func (b *sharedApplicationBlob) Save(raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.raw = append([]byte(nil), raw...)
	return nil
}
func (b *sharedApplicationBlob) Update(edit func([]byte) ([]byte, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	next, err := edit(append([]byte(nil), b.raw...))
	if err != nil {
		return err
	}
	b.raw = append([]byte(nil), next...)
	return nil
}

func TestApplicationDestinationsFromTwoControlPlanesDoNotEraseEachOther(t *testing.T) {
	blob := &sharedApplicationBlob{}
	first, second := NewStore(), NewStore()
	for _, s := range []*Store{first, second} {
		if err := s.SetPersister(blob); err != nil {
			t.Fatal(err)
		}
	}
	destination := func(id string) Endpoint {
		return Endpoint{TenantID: "one", Alias: id, Kind: KindNetwork, Address: id + ".example.test"}
	}
	if _, err := first.UpsertApplicationEndpoint("alpha", destination("alpha"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := second.UpsertApplicationEndpoint("beta", destination("beta"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := first.UpsertGroup(Group{TenantID: "one", Alias: "operators"}); err != nil {
		t.Fatal(err)
	}
	if len(second.ListGroups("one")) != 0 {
		t.Fatal("test requires a stale second CP before refresh")
	}
	if err := second.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if len(second.ListGroups("one")) != 1 || second.ConfigGeneration() != 3 {
		t.Fatal("peer group and generation were not refreshed")
	}
	reload := func() *Store {
		t.Helper()
		s := NewStore()
		if err := s.SetPersister(blob); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, id := range []string{"alpha", "beta"} {
		if _, found := reload().GetEndpoint("one", "app-"+id); !found {
			t.Fatalf("stale CP erased application %s", id)
		}
	}
	if generation := reload().ConfigGeneration(); generation != 3 {
		t.Fatalf("shared catalog generation=%d, want 3", generation)
	}
	if deleted, err := first.DeleteApplicationEndpoint("one", "alpha", false); err != nil || !deleted {
		t.Fatalf("stale CP delete = %v, %v", deleted, err)
	}
	latest := reload()
	if _, found := latest.GetEndpoint("one", "app-alpha"); found {
		t.Fatal("deleted destination survived")
	}
	if _, found := latest.GetEndpoint("one", "app-beta"); !found {
		t.Fatal("stale CP delete erased the peer's destination")
	}
	if len(latest.ListGroups("one")) != 1 {
		t.Fatal("application deletion erased the other CP's group")
	}
}

func TestSharedCatalogUpgradeDoesNotLowerActiveBundleGeneration(t *testing.T) {
	blob := &sharedApplicationBlob{raw: []byte(`{"seq":2,"endpoints":{},"groups":{},"services":{},"aliases":{}}`)}
	store := NewStore()
	store.generation = 7 // an active CP before persisted snapshots carried generation
	if err := store.SetPersister(blob); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertApplicationEndpoint("wiki", Endpoint{TenantID: "one", Alias: "wiki", Kind: KindNetwork, Address: "wiki.example.test"}, false); err != nil {
		t.Fatal(err)
	}
	if got := store.ConfigGeneration(); got != 8 {
		t.Fatalf("active CP generation moved backwards: got %d, want 8", got)
	}
	reloaded := NewStore()
	if err := reloaded.SetPersister(blob); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ConfigGeneration(); got != 8 {
		t.Fatalf("shared generation not durable: got %d, want 8", got)
	}
}
