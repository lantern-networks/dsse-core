package enrolledinventory

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestRemoveCheckedSaveOutcomesAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true}, {"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"rejected", errors.New("store unavailable"), false, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false},
		{"unconfirmed_written", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_written", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &tenantRetirementStore{}
			l := NewLedger()
			if err := l.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			old := "2000-01-01T00:00:00Z"
			now := "2026-09-18T00:00:00Z"
			for _, id := range []string{"target", "expired", "foreign"} {
				if _, err := l.Enroll(id, "tenant_"+id, "retain", old); err != nil {
					t.Fatal(err)
				}
			}
			if !l.Remove("expired", old) {
				t.Fatal("seed tombstone")
			}
			if _, err := l.CreateGroup("Keep", "tenant_foreign", "", "high", old); err != nil {
				t.Fatal(err)
			}
			before := l.Authoritative()
			groups := l.ListGroups()
			gen := l.ConfigGeneration()
			saved := bytes.Clone(p.data)
			p.err, p.retain = tc.err, tc.retain
			e, err := l.RemoveChecked(" TARGET ", now)
			if (err == nil) != tc.accepted || e.Identity != "target" || e.isTombstone() != tc.accepted {
				t.Fatalf("outcome %+v %v", e, err)
			}
			if !tc.accepted {
				if !reflect.DeepEqual(before, l.Authoritative()) || l.ConfigGeneration() != gen {
					t.Fatal("unconfirmed removal changed local state or generation")
				}
				if !errors.Is(err, tc.err) {
					t.Fatal("storage cause lost")
				}
			}
			if tc.accepted {
				if l.ConfigGeneration() != gen+1 {
					t.Fatal("confirmed generation")
				}
				if _, ok := l.EntryFor("expired"); ok {
					t.Fatal("expired tombstone not purged")
				}
			}
			if !reflect.DeepEqual(groups, l.ListGroups()) {
				t.Fatal("groups changed")
			}
			if !tc.retain && !bytes.Equal(saved, p.data) {
				t.Fatal("rejected candidate written")
			}
			reloaded := NewLedger()
			if err := reloaded.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			stored, _ := reloaded.EntryFor("target")
			if stored.isTombstone() != tc.retain {
				t.Fatal("unconfirmed stored outcome misreported")
			}
			_, exists := reloaded.EntryFor("expired")
			if exists == tc.retain {
				t.Fatal("cleanup not saved with removal")
			}
			p.err = nil
			p.retain = true
			if !tc.accepted {
				if _, err := l.RemoveChecked("target", now); err != nil {
					t.Fatal(err)
				}
			}
			writes := p.writes
			gen = l.ConfigGeneration()
			for _, id := range []string{"target", "missing"} {
				if _, err := l.RemoveChecked(id, now); !errors.Is(err, ErrIdentityNotFound) {
					t.Fatalf("missing %s: %v", id, err)
				}
			}
			if writes != p.writes || gen != l.ConfigGeneration() {
				t.Fatal("missing identity wrote or advanced generation")
			}
			reloaded = NewLedger()
			if err := reloaded.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(l.Authoritative(), reloaded.Authoritative()) {
				t.Fatal("retry did not persist complete state")
			}
		})
	}
}

func TestEnrollGroupForTenantReturnsLocallyAppliedEntryOnSaveFailure(t *testing.T) {
	p := &tenantRetirementStore{}
	l := NewLedger()
	l.SetPersister(p)
	p.err = errors.New("unavailable")
	e, err := l.EnrollGroupForTenant("NEW", "tenant_a", "tenant_a", "QA", "", "2026-09-18T00:00:00Z", false)
	if !errors.Is(err, p.err) || e.Identity != "new" || !e.Enabled || e.Group != "QA" {
		t.Fatalf("partial entry %+v %v", e, err)
	}
	live, _ := l.EntryFor("new")
	if !reflect.DeepEqual(live, e) {
		t.Fatal("returned entry differs from applied state")
	}
	refused, err := l.EnrollGroupForTenant("new", "tenant_b", "tenant_b", "", "", "2026-09-18T00:00:00Z", false)
	if !errors.Is(err, ErrIdentityOwnedByAnotherTenant) || refused.Identity != "" {
		t.Fatal("refusal exposed another tenant's entry")
	}
}
