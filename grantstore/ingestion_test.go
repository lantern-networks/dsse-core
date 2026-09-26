package grantstore

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func grantFixture(id string, now time.Time) Grant {
	return Grant{GrantID: id, TenantID: "tenant", UserID: "person", IdPID: "idp", Scope: "app", AMR: []string{"webauthn"}, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
}
func TestIngestionCannotReactivateOrReassignGrant(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	g, e := s.Mint(grantFixture("cookie", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	s.Revoke(g.GrantID)
	gen := s.ConfigGeneration()
	if _, e = s.Mint(g, time.Hour, now); !errors.Is(e, ErrConflict) {
		t.Fatalf("re-mint error %v", e)
	}
	if a, u, e := s.MergeChecked([]Grant{g}, now); e != nil || a != 0 || u != 0 {
		t.Fatalf("stale replay %d %d %v", a, u, e)
	}
	if s.Valid(g.GrantID, now) || s.ConfigGeneration() != gen {
		t.Fatal("revocation or generation changed")
	}
	other := g
	other.TenantID = "Tenant"
	if _, _, e = s.MergeChecked([]Grant{other}, now); !errors.Is(e, ErrConflict) {
		t.Fatal("tenant reassigned")
	}
	held, _ := s.Get(g.GrantID)
	if held.TenantID != g.TenantID || !held.Revoked {
		t.Fatal("attribution or denial changed")
	}
}
func TestIngestionFreezesApprovalAndRejectsInvalidBatch(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	g, _ := s.Mint(grantFixture("cookie", now), time.Hour, now)
	for _, change := range []func(*Grant){func(v *Grant) { v.UserID = "other" }, func(v *Grant) { v.DeviceID = "other" }, func(v *Grant) { v.Scope = "*" }, func(v *Grant) { v.IdPID = "other" }, func(v *Grant) { v.ACR = "higher" }, func(v *Grant) { v.AMR = []string{"pwd"} }, func(v *Grant) { v.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339) }} {
		next := cloneGrant(g)
		change(&next)
		if _, _, e := s.MergeChecked([]Grant{next}, now); !errors.Is(e, ErrConflict) {
			t.Fatal("authorization replaced")
		}
	}
	for _, bad := range []Grant{{}, {GrantID: "bad", TenantID: "tenant", ExpiresAt: "invalid"}, {GrantID: "bad", TenantID: "tenant", IssuedAt: g.ExpiresAt, ExpiresAt: g.IssuedAt}} {
		deny := g
		deny.Revoked = true
		gen := s.ConfigGeneration()
		if _, _, e := s.MergeChecked([]Grant{deny, bad, grantFixture("new", now)}, now); !errors.Is(e, ErrInvalidGrant) {
			t.Fatal("invalid batch accepted")
		}
		if !s.Valid(g.GrantID, now) || s.ConfigGeneration() != gen {
			t.Fatal("invalid batch partially mutated")
		}
		if _, ok := s.Get("new"); ok {
			t.Fatal("invalid batch admitted new approval")
		}
	}
	// Valid revocation dominates older content, and keeps the original attribution.
	deny := g
	deny.Revoked = true
	deny.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
	deny.IssuedAt = now.Add(-2 * time.Hour).Format(time.RFC3339)
	if _, u, e := s.MergeChecked([]Grant{deny}, now); e != nil || u != 1 {
		t.Fatal(e)
	}
	held, _ := s.Get(g.GrantID)
	if !held.Revoked || held.ExpiresAt != g.ExpiresAt {
		t.Fatal("revocation rewrote claims")
	}
}
func TestIngestionSavesNewGrantsBeforeAdoptionAndRetriesDenials(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	p := &revokeSaveGate{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	g, _ := s.Mint(grantFixture("held", now), time.Hour, now)
	p.fail = true
	gen := s.ConfigGeneration()
	if _, e := s.Mint(grantFixture("minted", now), time.Hour, now); !errors.Is(e, ErrPersistence) {
		t.Fatal(e)
	}
	if _, ok := s.Get("minted"); ok || s.ConfigGeneration() != gen {
		t.Fatal("failed mint was adopted")
	}
	tombstone := grantFixture("old-denial", now.Add(-2*time.Hour))
	tombstone.Revoked = true
	g.Revoked = true
	incoming := []Grant{grantFixture("new", now), tombstone, g}
	if a, u, e := s.MergeChecked(incoming, now); !errors.Is(e, ErrPersistence) || a != 1 || u != 1 {
		t.Fatalf("partial merge %d %d %v", a, u, e)
	}
	if s.Valid("held", now) {
		t.Fatal("save failure restored access")
	}
	if _, ok := s.Get("new"); ok {
		t.Fatal("unsaved new approval adopted")
	}
	old, ok := s.Get("old-denial")
	if !ok || !old.Revoked {
		t.Fatal("incoming denial lost")
	}
	generation := s.ConfigGeneration()
	count := p.saves
	if _, _, e := s.MergeChecked(incoming, now); !errors.Is(e, ErrPersistence) || p.saves != count+1 || s.ConfigGeneration() != generation {
		t.Fatal("unchanged denial was not retried")
	}
	p.fail = false
	if a, u, e := s.MergeChecked(incoming, now); e != nil || a != 1 || u != 0 {
		t.Fatalf("retry %d %d %v", a, u, e)
	}
	restarted := NewStore()
	if e := restarted.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if restarted.Valid("held", now) || restarted.Valid("old-denial", now) || !restarted.Valid("new", now) {
		t.Fatal("restart state wrong")
	}
	count = p.saves
	generation = s.ConfigGeneration()
	if _, _, e := s.MergeChecked(incoming, now); e != nil || p.saves != count || s.ConfigGeneration() != generation {
		t.Fatal("idempotent replay wrote or advanced generation")
	}
}
func TestIngestionBatchDenialsWinAndExpiredApprovalsStayDead(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	g := grantFixture("cookie", now)
	deny := cloneGrant(g)
	deny.Revoked = true
	changed := cloneGrant(g)
	changed.Scope = "other"
	for _, input := range [][]Grant{{g, deny}, {deny, g}, {g, changed, deny}, {deny, changed, g}, {g, deny, changed}} {
		s = NewStore()
		if a, _, e := s.MergeChecked(input, now); e != nil || a != 1 || s.Valid(g.GrantID, now) {
			t.Fatal("order-dependent revocation")
		}
	}
	old := grantFixture("expired", now.Add(-2*time.Hour))
	if a, _, e := s.MergeChecked([]Grant{old}, now); e != nil || a != 0 {
		t.Fatal("unknown expired approval admitted")
	}
	older := grantFixture("cookie", now.Add(-2*time.Hour))
	if _, _, e := s.MergeChecked([]Grant{older}, now); e != nil || s.Valid("cookie", now) {
		t.Fatal("old copy revived tombstone")
	}
}
func TestIngestionCopiesClaimsAndSerializesRevoke(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	g, _ := s.Mint(grantFixture("cookie", now), time.Hour, now)
	g.AMR[0] = "changed"
	got, _ := s.Get("cookie")
	if got.AMR[0] != "webauthn" {
		t.Fatal("mint alias")
	}
	original := cloneGrant(got)
	got.AMR[0] = "changed"
	all := s.ListAll()
	all[0].AMR[0] = "changed"
	list := s.List("tenant")
	list[0].AMR[0] = "changed"
	got, _ = s.Get("cookie")
	if !reflect.DeepEqual(got, original) {
		t.Fatal("read alias")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.Merge([]Grant{original}, now) }()
		go func() { defer wg.Done(); s.RevokeForTenant("tenant", "cookie") }()
	}
	wg.Wait()
	if s.Valid("cookie", now) {
		t.Fatal("concurrent stale merge revived access")
	}
}
