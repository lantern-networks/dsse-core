package grantstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func requestGrant(now time.Time) Grant {
	return Grant{GrantID: "single", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Issuer: "https://idp.example", ProviderConfigSHA256: strings.Repeat("a", 64), Scope: "app:22", AuthTime: now.Format(time.RFC3339), ReauthenticationStartedAt: now.Format(time.RFC3339), AuthenticationRequestID: "original-request"}
}
func TestAuthenticationRequestConsumedOnceAcrossStores(t *testing.T) {
	p := &grantSharedFixture{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p)
	b.SetPersister(p)
	now := time.Now().UTC().Truncate(time.Second)
	g, err := a.Mint(requestGrant(now), time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 0 {
				s = b
			}
			ok, e := s.ConsumeAuthenticationRequest(context.Background(), g, now)
			if e != nil {
				t.Error(e)
			}
			if ok {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("consumed %d times", wins.Load())
	}
	if used, ok := b.Get(g.GrantID); !ok || !used.Revoked || used.ConsumedAt != now.Format(time.RFC3339) {
		t.Fatalf("consumption must be durable and distinct from admin revocation: %+v %v", used, ok)
	}
	// A duplicate issuer process must not provide a second release for this ID.
	duplicate := requestGrant(now)
	duplicate.GrantID = "duplicate"
	duplicate, err = b.Mint(duplicate, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if ok, e := b.ConsumeAuthenticationRequest(context.Background(), duplicate, now); e != nil || ok {
		t.Fatal("duplicate ceremony reused", e)
	}
	peer := NewStore()
	peer.SetPersister(p)
	if ok, e := peer.ConsumeAuthenticationRequest(context.Background(), g, now); e != nil || ok {
		t.Fatal("restart erased consumption", e)
	}
	if used, ok := peer.Get(g.GrantID); !ok || used.ConsumedAt == "" {
		t.Fatal("restart erased the consumption reason")
	}
}
func TestAdministrativeRevocationDoesNotClaimConsumption(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC().Truncate(time.Second)
	g, err := s.Mint(requestGrant(now), time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	revoked, found, err := s.RevokeForTenant(g.TenantID, g.GrantID)
	if err != nil || !found || !revoked.Revoked || revoked.ConsumedAt != "" {
		t.Fatalf("admin revocation mislabelled: %+v %v %v", revoked, found, err)
	}
}
func TestConsumptionReasonPropagatesWithRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, b := NewStore(), NewStore()
	g, err := a.Mint(requestGrant(now), time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.MergeChecked([]Grant{g}, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.ConsumeAuthenticationRequest(context.Background(), g, now); err != nil || !ok {
		t.Fatalf("consume: %v %v", ok, err)
	}
	used, _ := a.Get(g.GrantID)
	if _, _, err := b.MergeChecked([]Grant{used}, now); err != nil {
		t.Fatal(err)
	}
	forwarded, _ := b.Get(g.GrantID)
	if !forwarded.Revoked || forwarded.ConsumedAt != used.ConsumedAt || b.Valid(g.GrantID, now) {
		t.Fatalf("consumption not forwarded as denial and reason: %+v", forwarded)
	}
	invalid := used
	invalid.Revoked = false
	if _, _, err := b.MergeChecked([]Grant{invalid}, now); err == nil {
		t.Fatal("active grant cannot claim a consumed reason")
	}
}
func TestAuthenticationRequestConsumptionRejectsMismatchAndUnconfirmedWrite(t *testing.T) {
	p := &grantSharedFixture{}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC().Truncate(time.Second)
	g, e := s.Mint(requestGrant(now), time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Grant){func(g *Grant) { g.TenantID = "other" }, func(g *Grant) { g.DeviceID = "other" }, func(g *Grant) { g.Scope = "other:22" }, func(g *Grant) { g.AuthenticationRequestID = "other" }} {
		wrong := g
		change(&wrong)
		if ok, _ := s.ConsumeAuthenticationRequest(context.Background(), wrong, now); ok {
			t.Fatal("mismatch consumed")
		}
	}
	p.fail = true
	if ok, e := s.ConsumeAuthenticationRequest(context.Background(), g, now); ok || e == nil {
		t.Fatal("unconfirmed commit released flow")
	}
	p.fail = false
	if ok, _ := s.ConsumeAuthenticationRequest(context.Background(), g, now); ok {
		t.Fatal("pending denial lost")
	}
}

type ambiguousConsumptionFixture struct {
	grantSharedFixture
	ambiguous bool
}

func (p *ambiguousConsumptionFixture) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	if e := p.grantSharedFixture.UpdateContext(ctx, f); e != nil {
		return e
	}
	if p.ambiguous {
		return ErrPersistence
	}
	return nil
}
func TestAuthenticationRequestLostCommitAckNeverReleases(t *testing.T) {
	p := &ambiguousConsumptionFixture{}
	a := NewStore()
	a.SetPersister(p)
	now := time.Now().UTC().Truncate(time.Second)
	g, e := a.Mint(requestGrant(now), time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	p.ambiguous = true
	if ok, e := a.ConsumeAuthenticationRequest(context.Background(), g, now); ok || e == nil {
		t.Fatal("ambiguous consume reported success")
	}
	p.ambiguous = false
	b := NewStore()
	if e = b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if ok, e := b.ConsumeAuthenticationRequest(context.Background(), g, now); ok || e != nil {
		t.Fatal("committed tombstone lost", e)
	}
}
