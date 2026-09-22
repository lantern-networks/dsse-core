package policy

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"reflect"
	"testing"
	"time"
)

func TestReceivedRuntimeCacheFailureStillAppliesAuthoritativeControls(t *testing.T) {
	p := &incomingFaultStore{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	old := TenantConfigBundle{ServerInitiatedEnabled: true, EastWestMaxGrantTTL: 37}
	for _, tenant := range []string{"a", "b"} {
		if _, err := s.ApplyReceivedBundle(tenant, nil, old, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	before := append([]byte(nil), p.raw...)
	next := TenantConfigBundle{EastWestEnabled: true, EastWestAllowUnmatched: false, EastWestRules: []decision.EastWestRule{{ID: "deny", Mode: "deny", Destinations: []string{"db.invalid"}}}}
	for _, failure := range []error{errors.New("disk refused"), errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)} {
		p.failure = failure
		if _, err := s.ApplyReceivedBundle("a", nil, next, time.Now()); !errors.Is(err, ErrPolicyPersistence) || !errors.Is(err, ErrReceivedRuntimeCache) {
			t.Fatal(err)
		}
		if !s.SnapshotTenantConfig("a").EastWestEnabled || s.ServerInitiatedEnabledFor("a") || len(s.SnapshotTenantConfig("a").EastWestRules) != 1 {
			t.Fatal("cache failure froze restrictive controls")
		}
		if !reflect.DeepEqual(p.raw, before) || !s.ServerInitiatedEnabledFor("b") {
			t.Fatal("failed save changed disk or peer")
		}
	}
	// CP authority includes a later relaxation; local disk failure does not make
	// this node an independent author of a permanently stricter policy either.
	if _, err := s.ApplyReceivedBundle("a", nil, old, time.Now()); !errors.Is(err, ErrPolicyPersistence) || !errors.Is(err, ErrReceivedRuntimeCache) {
		t.Fatal(err)
	}
	if !s.ServerInitiatedEnabledFor("a") || s.SnapshotTenantConfig("a").EastWestEnabled {
		t.Fatal("cache overrode subsequent authority")
	}
	p.failure = nil
	if _, err := s.ApplyReceivedBundle("a", nil, next, time.Now()); err != nil {
		t.Fatal(err)
	}
	restart := NewStore(nil)
	if err := restart.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"a", "b"} {
		if !reflect.DeepEqual(restart.SnapshotTenantConfig(tenant), s.SnapshotTenantConfig(tenant)) {
			t.Fatal("retry/reload differs", tenant)
		}
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
