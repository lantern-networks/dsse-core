package assetcatalog

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"testing"
)

func TestApplicationEndpointOwnershipPersistenceAndLegacyAdoption(t *testing.T) {
	ctx := context.Background()
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	manual := Endpoint{ID: "app-app", TenantID: "one", Alias: "Manual", Kind: KindNetwork, Source: SourceManual, Address: "old.example"}
	if _, err := s.UpsertEndpoint(manual); err != nil {
		t.Fatal(err)
	}
	desired := manual
	desired.Address = "app.example"
	if _, err := s.UpsertApplicationEndpointContext(ctx, "app", desired, false); !errors.Is(err, ErrApplicationEndpointOwnership) {
		t.Fatalf("manual takeover: %v", err)
	}
	if _, err := s.DeleteApplicationEndpointContext(ctx, "one", "app", false); !errors.Is(err, ErrApplicationEndpointOwnership) {
		t.Fatalf("manual deletion: %v", err)
	}
	owned, err := s.UpsertApplicationEndpointContext(ctx, "app", desired, true)
	if err != nil {
		t.Fatal(err)
	}
	if owned.Source != SourceApplication {
		t.Fatal("adoption did not save ownership")
	}
	restored := NewStore()
	if err := restored.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	owned.Source = SourceManual
	if _, err := restored.UpsertEndpointContext(ctx, owned); !errors.Is(err, ErrApplicationEndpointOwnership) {
		t.Fatalf("generic owner override: %v", err)
	}
	if _, err := restored.DeleteEndpointContext(ctx, "one", "app-app"); !errors.Is(err, ErrApplicationEndpointOwnership) {
		t.Fatalf("generic delete: %v", err)
	}
	forged := manual
	forged.ID = "app-forged"
	forged.Source = SourceApplication
	if _, err := restored.UpsertEndpointContext(ctx, forged); !errors.Is(err, ErrApplicationEndpointOwnership) {
		t.Fatalf("forged owner: %v", err)
	}
	if _, err := restored.UpsertApplicationEndpointContext(ctx, "app", desired, false); err != nil {
		t.Fatal(err)
	}
	if deleted, err := restored.DeleteApplicationEndpointContext(ctx, "one", "app", false); err != nil || !deleted {
		t.Fatalf("owned cleanup: %v %v", deleted, err)
	}
	if deleted, err := restored.DeleteApplicationEndpointContext(ctx, "one", "app", false); err != nil || deleted {
		t.Fatalf("idempotent cleanup: %v %v", deleted, err)
	}
}
