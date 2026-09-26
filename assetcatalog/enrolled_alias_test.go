package assetcatalog

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestEnrolledRenameSurvivesRestartWithoutPersistingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	s := NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	devices := []EnrolledDevice{{Identity: "verified-device", Name: "original", Platform: "macos"}}
	ep := s.SyncEnrolledEndpoints("tenant", devices, time.Now())[0]
	ep.Alias = "chosen-name"
	saved, err := s.UpsertEndpointContext(context.Background(), ep)
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if len(fresh.ListEndpoints("tenant")) != 0 {
		t.Fatal("snapshot manufactured an inventory endpoint")
	}
	restored := fresh.SyncEnrolledEndpoints("tenant", devices, time.Now())[0]
	if !reflect.DeepEqual(saved, restored) {
		t.Fatalf("rename lost after restart: got %+v want %+v", restored, saved)
	}
}

func TestEnrolledHTTPMutationOnlyRenamesExistingIdentity(t *testing.T) {
	mutations := map[string]func(*Endpoint){
		"identity":     func(e *Endpoint) { e.Identity = "other-identity" },
		"source":       func(e *Endpoint) { e.Source = SourceManual },
		"kind":         func(e *Endpoint) { e.Kind = KindNetwork; e.Address = "foreign.invalid" },
		"platform":     func(e *Endpoint) { e.Platform = "windows" },
		"tags":         func(e *Endpoint) { e.Tags = []string{"privileged"} },
		"new id":       func(e *Endpoint) { e.ID = "enrolled-forged" },
		"other tenant": func(e *Endpoint) { e.TenantID = "foreign" },
	}
	for name, edit := range mutations {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			ep := s.SyncEnrolledEndpoints("tenant", []EnrolledDevice{{Identity: "verified-device", Name: "original", Platform: "macos"}}, time.Now())[0]
			before := ep
			edit(&ep)
			if _, err := s.UpsertEndpointContext(context.Background(), ep); err == nil {
				t.Fatal("inventory ownership mutation accepted")
			}
			got, _ := s.GetEndpoint("tenant", before.ID)
			if !reflect.DeepEqual(got, before) {
				t.Fatal("refused mutation changed endpoint")
			}
		})
	}
	s := NewStore()
	ep := s.SyncEnrolledEndpoints("tenant", []EnrolledDevice{{Identity: "device", Name: "original"}}, time.Now())[0]
	if _, err := s.DeleteEndpointContext(context.Background(), "tenant", ep.ID); err == nil {
		t.Fatal("inventory endpoint deletion accepted")
	}
}

func TestEnrolledRenameSaveFailurePreservesAliasAndRetry(t *testing.T) {
	p := &catalogTestWriter{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	devices := []EnrolledDevice{{Identity: "device", Name: "original"}}
	ep := s.SyncEnrolledEndpoints("tenant", devices, time.Now())[0]
	ep.Alias = "renamed"
	p.fail = true
	if _, err := s.UpsertEndpointContext(context.Background(), ep); !errors.Is(err, ErrPersistence) {
		t.Fatal("unconfirmed rename acknowledged", err)
	}
	if got := s.SyncEnrolledEndpoints("tenant", devices, time.Now())[0]; got.Alias != "original" {
		t.Fatal("failed rename changed live alias")
	}
	p.fail = false
	if _, err := s.UpsertEndpointContext(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	count := p.saves
	s.SyncEnrolledEndpoints("tenant", devices, time.Now())
	if p.saves != count {
		t.Fatal("list sync wrote a snapshot")
	}
	restored := NewStore()
	if err := restored.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if restored.SyncEnrolledEndpoints("tenant", devices, time.Now())[0].Alias != "renamed" {
		t.Fatal("retry did not persist alias")
	}
}
