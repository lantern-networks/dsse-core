package delegatedgrant

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestActiveExpiredRevokedAndCapacity(t *testing.T) {
	now := time.Now().UTC()
	store := NewStore(2)
	mk := func(id, exp string) model.DelegatedAccessGrant {
		return model.DelegatedAccessGrant{ID: id, TenantID: "acme", SubjectUserID: "u1", Status: "active", ExpiresAt: exp}
	}
	if _, err := store.Upsert(mk("g1", now.Add(time.Hour).Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetActive("g1", now); !ok {
		t.Fatal("a future-dated active grant should be active")
	}
	// expired grant is not active
	_, _ = store.Upsert(mk("g2", now.Add(-time.Hour).Format(time.RFC3339)))
	if _, ok := store.GetActive("g2", now); ok {
		t.Fatal("an expired grant must not be active")
	}
	// revoke
	if _, err := store.Revoke("g1", "test", now); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetActive("g1", now); ok {
		t.Fatal("a revoked grant must not be active")
	}
	// FIFO capacity bound
	_, _ = store.Upsert(mk("g3", now.Add(time.Hour).Format(time.RFC3339)))
	if store.Count() > store.Capacity() {
		t.Fatalf("count %d exceeds capacity %d", store.Count(), store.Capacity())
	}
}

// TestIsActiveFailsClosedOnMalformedExpiry pins fail-open review finding #12: a non-empty but UNPARSEABLE expiry
// must NOT leave a grant active forever — it fails closed. An empty expiry is left as "no expiry" (a permanent
// grant is a mint-time policy question, not a reason to fail an authored grant closed here).
func TestIsActiveFailsClosedOnMalformedExpiry(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour).Format(time.RFC3339)
	if IsActive(model.DelegatedAccessGrant{Status: "active", ExpiresAt: "not-a-time"}, now) {
		t.Fatal("malformed expiry must be treated as expired, not active-forever")
	}
	if !IsActive(model.DelegatedAccessGrant{Status: "active", ExpiresAt: future}, now) {
		t.Fatal("valid future expiry must be active")
	}
	if !IsActive(model.DelegatedAccessGrant{Status: "active", ExpiresAt: ""}, now) {
		t.Fatal("empty expiry must remain active (no-expiry)")
	}
}
