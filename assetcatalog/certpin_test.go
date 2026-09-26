package assetcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestCertPinOwnershipSurvivesRestartAndProtectsLegacy(t *testing.T) {
	ctx := context.Background()
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "legacy"}[legacy], func(t *testing.T) {
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			ep := Endpoint{ID: "certpin-ep-candidate", TenantID: "one", Alias: "approved.example", Kind: KindNetwork, Address: "approved.example", Source: SourceManual, Tags: []string{"cert_pin"}}
			if legacy { // Seed an old persisted row, not a newly authorized generic write.
				s.upsertEndpoint(ep)
				s.mu.Lock()
				err := s.persistLocked()
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.UpsertCertPinEndpointContext(ctx, "candidate", ep); err != nil {
				t.Fatal(err)
			}
			fresh := NewStore()
			if err := fresh.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			before, _ := p.Load()
			forged := ep
			forged.Address = "unreviewed.example"
			if _, err := fresh.UpsertEndpointContext(ctx, forged); !errors.Is(err, ErrCertPinEndpointOwnership) {
				t.Fatal("retarget allowed", err)
			}
			if _, err := fresh.DeleteEndpointContext(ctx, "one", ep.ID); !errors.Is(err, ErrCertPinEndpointOwnership) {
				t.Fatal("delete allowed", err)
			}
			after, _ := p.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("rejection rewrote storage")
			}
			if _, err := fresh.UpsertCertPinEndpointContext(ctx, "candidate", ep); err != nil {
				t.Fatal("same approved target cannot retry", err)
			}
			reloaded := NewStore()
			if err := reloaded.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			got, _ := reloaded.GetEndpoint("one", ep.ID)
			if got.Source != SourceCertPin || got.Address != ep.Address {
				t.Fatal(got)
			}
			ordinary := Endpoint{TenantID: "other", ID: "manual", Kind: KindNetwork, Address: "other.example", Source: SourceManual}
			if _, err := fresh.UpsertEndpointContext(ctx, ordinary); err != nil {
				t.Fatal(err)
			}
			if _, err := fresh.DeleteEndpointContext(ctx, "other", ordinary.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCertPinOwnershipRejectsClaimsAndConflictingLegacy(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	for _, ep := range []Endpoint{{ID: "certpin-ep-forged", Source: SourceManual}, {ID: "ordinary", Source: SourceCertPin}} {
		ep.TenantID = "one"
		ep.Kind = KindNetwork
		if _, err := s.UpsertEndpointContext(ctx, ep); !errors.Is(err, ErrCertPinEndpointOwnership) {
			t.Fatal("claim allowed", err)
		}
	}
	old := Endpoint{ID: "certpin-ep-candidate", TenantID: "one", Kind: KindNetwork, Address: "conflict.example", Source: SourceManual, Tags: []string{"cert_pin"}}
	s.upsertEndpoint(old)
	desired := old
	desired.Address = "approved.example"
	if _, err := s.UpsertCertPinEndpointContext(ctx, "candidate", desired); !errors.Is(err, ErrCertPinEndpointOwnership) {
		t.Fatal("conflicting manual target adopted", err)
	}
	got, _ := s.GetEndpoint("one", old.ID)
	if got.Address != old.Address || got.Source != old.Source {
		t.Fatal("conflict mutated")
	}
}

// Exercises the locked latest-row contract; this is not a PostgreSQL acceptance.
type certPinSharedWriter struct{ catalogTestWriter }

func (p *certPinSharedWriter) UpdateContext(ctx context.Context, apply func([]byte) ([]byte, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := apply(p.data)
	if err != nil {
		return err
	}
	return p.Save(next)
}
func TestCertPinOwnershipChecksLatestSharedRow(t *testing.T) {
	p := &certPinSharedWriter{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	e := Endpoint{ID: "ordinary", TenantID: "one", Kind: KindNetwork, Source: SourceManual, Address: "host.example"}
	if _, err := s.UpsertEndpointContext(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	var snap persistedCatalog
	if err := json.Unmarshal(p.data, &snap); err != nil {
		t.Fatal(err)
	}
	peer := snap.Endpoints["one"]["ordinary"]
	peer.Source = SourceCertPin
	snap.Endpoints["one"]["ordinary"] = peer
	p.data, _ = json.Marshal(snap)
	before := append([]byte(nil), p.data...)
	if _, err := s.UpsertEndpointContext(context.Background(), e); !errors.Is(err, ErrCertPinEndpointOwnership) {
		t.Fatal("stale retarget", err)
	}
	if _, err := s.DeleteEndpointContext(context.Background(), "one", e.ID); !errors.Is(err, ErrCertPinEndpointOwnership) {
		t.Fatal("stale delete", err)
	}
	if !bytes.Equal(before, p.data) {
		t.Fatal("latest ownership overwritten")
	}
}

func TestDeletingAnAbsentCertPinIDIsAbsentNotForbidden(t *testing.T) {
	s := NewStore()
	deleted, err := s.DeleteEndpointContext(context.Background(), "one", "certpin-ep-never-created")
	if err != nil || deleted {
		t.Fatalf("absent cert-pin ID answered as ownership refusal: deleted=%v err=%v", deleted, err)
	}
}
