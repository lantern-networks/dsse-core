package policy

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
	"time"
)

func TestReceivedRuntimeCacheFailureKeepsPreviousControls(t *testing.T) {
	p := &incomingFaultStore{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	old := TenantConfigBundle{EastWestEnabled: true, ServerInitiatedEnabled: true, EastWestMaxGrantTTL: 37}
	for _, tenant := range []string{"a", "b"} {
		if _, err := s.ApplyReceivedBundle(tenant, nil, old, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	want := s.SnapshotTenantConfig("a")
	before := append([]byte(nil), p.raw...)
	gen := s.ConfigGeneration()
	for _, failure := range []error{errors.New("disk refused"), errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)} {
		p.failure = failure
		if n, err := s.ApplyReceivedBundle("a", nil, TenantConfigBundle{}, time.Now()); n != 0 || !errors.Is(err, ErrPolicyPersistence) {
			t.Fatal(n, err)
		}
		if s.ConfigGeneration() != gen || !reflect.DeepEqual(s.SnapshotTenantConfig("a"), want) || !reflect.DeepEqual(p.raw, before) {
			t.Fatal("failed cache save published controls")
		}
	}
	p.failure = nil
	if _, err := s.ApplyReceivedBundle("a", nil, TenantConfigBundle{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	restart := NewStore(nil)
	if err := restart.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"a", "b"} {
		if !reflect.DeepEqual(restart.SnapshotTenantConfig(tenant), s.SnapshotTenantConfig(tenant)) {
			t.Fatal("restart differs", tenant)
		}
	}
	if !restart.ServerInitiatedEnabledFor("b") || restart.ServerInitiatedEnabledFor("a") {
		t.Fatal("tenant controls crossed")
	}
}

func TestReceivedRuntimeCacheRejectsSharedAuthor(t *testing.T) {
	p := &trSharedPersister{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfigGeneration()
	if _, err := s.ApplyReceivedBundle("a", nil, TenantConfigBundle{EastWestEnabled: true}, time.Now()); err == nil {
		t.Fatal("shared author overwritten")
	}
	if len(p.raw) != 0 || s.ConfigGeneration() != gen {
		t.Fatal("rejected receiver mutated author")
	}
}
