package assetcatalog

import (
	"path/filepath"
	"testing"
)

func TestApplicationEndpointOwnershipAndDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	s := NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	manual := Endpoint{ID: "app-wiki", TenantID: "one", Alias: "manual-wiki", Kind: KindNetwork, Address: "manual.example.test", Source: SourceManual}
	if _, err := s.UpsertEndpoint(manual); err != nil {
		t.Fatal(err)
	}
	want := Endpoint{TenantID: "one", Alias: "Wiki", Kind: KindNetwork, Address: "wiki.example.test"}
	if _, err := s.UpsertApplicationEndpoint("wiki", want, false); err == nil {
		t.Fatal("application write replaced a manually owned destination")
	}
	if _, err := s.DeleteApplicationEndpoint("one", "wiki", false); err == nil {
		t.Fatal("application delete removed a manually owned destination")
	}
	if existing, found := s.GetEndpoint("one", "app-wiki"); !found || existing.Address != manual.Address {
		t.Fatalf("manual destination changed: %+v found=%v", existing, found)
	}
	owned, err := s.UpsertApplicationEndpoint("wiki", want, true)
	if err != nil || owned.Source != SourceApplication {
		t.Fatalf("authorized adoption = %+v, %v", owned, err)
	}
	if _, err := s.UpsertEndpoint(manual); err == nil {
		t.Fatal("generic write changed application-owned destination")
	}
	if _, err := s.DeleteEndpoint("one", "app-wiki"); err == nil {
		t.Fatal("generic delete removed application-owned destination")
	}
	reloaded := NewStore()
	if err := reloaded.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if existing, found := reloaded.GetEndpoint("one", "app-wiki"); !found || existing.Source != SourceApplication || existing.Address != want.Address {
		t.Fatalf("application ownership did not survive restart: %+v found=%v", existing, found)
	}
	if deleted, err := reloaded.DeleteApplicationEndpoint("one", "wiki", false); err != nil || !deleted {
		t.Fatalf("application-owned destination delete = %v, %v", deleted, err)
	}
}
