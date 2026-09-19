package revocation

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestAdmissionMeshCheckedSaveAndRetryOutcomes(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true}, {"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"no_write", errors.New("private store error"), false, false}, {"error_after_write", errors.New("private store error"), true, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false}, {"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false}, {"bridge_retained", bridge, true, false},
		{"wrapped_lost", fmt.Errorf("private path: %w", bridge), false, false}, {"wrapped_retained", fmt.Errorf("private path: %w", bridge), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &admissionSavePersister{}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			a.Revoke("origin", "local")
			a.RevokeFromMesh("other-peer", "keep")
			a.ReplaceSynced(map[string]string{"synced": "CP"})
			gen := a.ConfigGeneration()
			callbacks, reports := 0, 0
			a.SetOnRevoked(func(id, reason string) {
				if id != "owned" || reason != "incident" {
					t.Errorf("unnormalized callback %q %q", id, reason)
				}
				callbacks++
			})
			a.SetReporter(func(string, string) { reports++ })
			a.SetMeshReporter(func(string, string) { reports++ })
			p.err, p.retain = tc.err, tc.retain
			for attempt := 0; attempt < 2; attempt++ {
				writes := p.writes
				changed, err := a.RevokeFromMeshChecked(" OWNED ", " incident ")
				if changed != (attempt == 0) || (err == nil) != tc.accepted {
					t.Fatalf("attempt %d: changed=%v err=%v", attempt, changed, err)
				}
				if err != nil && err != ErrAdmissionSave {
					t.Fatal("private error escaped")
				}
				if p.writes != writes+1 {
					t.Fatal("explicit delivery did not retry saving")
				}
				if a.ConfigGeneration() != gen+1 || callbacks != 1 || reports != 0 {
					t.Fatal("retry churn or received item re-pushed")
				}
				if _, ok := a.IsRevoked("owned"); !ok {
					t.Fatal("failed save relaxed the received block")
				}
			}
			reopened := NewAdmissionRevocations()
			if err := reopened.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, ok := reopened.IsRevoked("owned"); ok != tc.retain {
				t.Fatal("wrong retained/lost outcome")
			}
			p.err = nil
			p.retain = true
			changed, err := a.RevokeFromMeshChecked("owned", "incident")
			if changed || err != nil {
				t.Fatalf("retry: %v %v", changed, err)
			}
			if a.ConfigGeneration() != gen+1 || callbacks != 1 || reports != 0 {
				t.Fatal("healthy retry churn")
			}
			reopened = NewAdmissionRevocations()
			if err := reopened.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a.FeedSnapshot(), reopened.FeedSnapshot()) || !reflect.DeepEqual(a.Snapshot(), map[string]string{"origin": "local"}) {
				t.Fatal("retry lost another layer")
			}
			if _, ok := a.IsRevoked("synced"); !ok {
				t.Fatal("synced changed")
			}
			if _, ok := a.Snapshot()["owned"]; ok {
				t.Fatal("received block became an origin block")
			}
			writes := p.writes
			if a.RevokeFromMesh("owned", "incident") || p.writes != writes {
				t.Fatal("legacy duplicate no-op contract changed")
			}
		})
	}
}

func TestAdmissionMeshRetryReadsDoNotWaitForSave(t *testing.T) {
	a := NewAdmissionRevocations()
	a.RevokeFromMesh("owned", "peer")
	gen := a.ConfigGeneration()
	p := newAdmissionGatedStore(t)
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	a.SetOnRevoked(func(id, _ string) {
		if id == "owned" {
			t.Error("unchanged retry repeated callback")
		}
	})
	type result struct {
		changed bool
		err     error
	}
	done := admissionAsync(func() result { changed, err := a.RevokeFromMeshChecked("owned", "peer"); return result{changed, err} })
	admissionWithin(t, p.entered)
	blocked := admissionWithin(t, admissionAsync(func() bool { _, ok := a.IsRevoked("owned"); return ok }))
	if !blocked {
		t.Fatal("pending retry lost block")
	}
	a.ReplaceSynced(map[string]string{"new-synced": "CP"})
	p.release()
	r := admissionWithin(t, done)
	if r.changed || r.err != nil || a.ConfigGeneration() != gen {
		t.Fatalf("bad result %+v", r)
	}
	if _, ok := a.IsRevoked("new-synced"); !ok {
		t.Fatal("synced update lost")
	}
}
