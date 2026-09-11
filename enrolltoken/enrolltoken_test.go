package enrolltoken

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testNow() time.Time { return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC) }

func issue(t *testing.T, s *Store, life time.Duration) (Token, string) {
	t.Helper()
	now := testNow()
	tok, secret, err := s.Issue(DefaultPolicy(), "tenant_a", "default", "batch-1", "adm_alice", "", now.Add(life), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok, secret
}

func TestATokenWorksExactlyOnce(t *testing.T) {
	s := NewStore()
	_, secret := issue(t, s, 72*time.Hour)

	tok, err := s.Consume(secret, "tenant_a", "laptop-01", testNow())
	if err != nil {
		t.Fatalf("first use must succeed: %v", err)
	}
	if tok.UsedBy != "laptop-01" {
		t.Fatalf("the record must say which device spent it, got %q", tok.UsedBy)
	}

	// A copied installer config reaching a second machine is the whole reason one-time exists.
	if _, err := s.Consume(secret, "tenant_a", "laptop-02", testNow()); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second use must be refused, got %v", err)
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	s := NewStore()
	_, secret := issue(t, s, time.Hour)
	if _, err := s.Consume(secret, "tenant_a", "laptop-01", testNow().Add(2*time.Hour)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected expiry refusal, got %v", err)
	}
}

func TestARevokedTokenIsRefused(t *testing.T) {
	s := NewStore()
	tok, secret := issue(t, s, 72*time.Hour)
	if _, ok := s.Revoke(tok.ID, "adm_alice", testNow()); !ok {
		t.Fatalf("revoke must find the token")
	}
	if _, err := s.Consume(secret, "tenant_a", "laptop-01", testNow()); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected revocation refusal, got %v", err)
	}
}

func TestAnUnknownSecretIsRefused(t *testing.T) {
	s := NewStore()
	issue(t, s, 72*time.Hour)
	if _, err := s.Consume("not-a-real-token", "tenant_a", "laptop-01", testNow()); !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("expected unknown-token refusal, got %v", err)
	}
}

// An Edge can serve more than one tenant. A token issued by one tenant's admin must not enrol a device into
// another, or the isolation the whole product rests on is undone at Day-0.
func TestATokenCannotCrossTenants(t *testing.T) {
	s := NewStore()
	_, secret := issue(t, s, 72*time.Hour)
	if _, err := s.Consume(secret, "tenant_b", "laptop-01", testNow()); !errors.Is(err, ErrWrongTenant) {
		t.Fatalf("expected cross-tenant refusal, got %v", err)
	}
	if _, err := s.Consume(secret, "tenant_a", "laptop-01", testNow()); err != nil {
		t.Fatalf("the owning tenant must still be able to use it: %v", err)
	}
}

// Two machines racing with the same copied config must not both enrol. The check and the mark have to happen
// under one lock; this test would catch them drifting apart.
func TestConcurrentUseOfOneTokenYieldsExactlyOneWinner(t *testing.T) {
	s := NewStore()
	_, secret := issue(t, s, 72*time.Hour)

	const racers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Consume(secret, "tenant_a", "racer", testNow()); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one racer may win, got %d", wins)
	}
}

// The lifetime is the issuer's call — that is the point — but not an unbounded one, or a slip (or a taken-over
// admin account) mints something that never dies.
func TestLifetimeIsTheIssuersChoiceWithinTheTenantMaximum(t *testing.T) {
	s := NewStore()
	now := testNow()
	policy := Policy{MaxLifetime: 7 * 24 * time.Hour, MaxOutstanding: 100}

	for _, life := range []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour} {
		if _, _, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(life), now); err != nil {
			t.Fatalf("lifetime %v is within the maximum and must be allowed: %v", life, err)
		}
	}
	if _, _, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(8*24*time.Hour), now); !errors.Is(err, ErrLifetimeTooLong) {
		t.Fatalf("beyond the maximum must be refused, got %v", err)
	}
	if _, _, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(-time.Hour), now); !errors.Is(err, ErrLifetimeNotFuture) {
		t.Fatalf("an expiry in the past must be refused, got %v", err)
	}
}

func TestOutstandingCapBoundsUnusedTokens(t *testing.T) {
	s := NewStore()
	now := testNow()
	policy := Policy{MaxLifetime: 30 * 24 * time.Hour, MaxOutstanding: 3}
	var secrets []string
	for i := 0; i < 3; i++ {
		_, sec, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(time.Hour), now)
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		secrets = append(secrets, sec)
	}
	if _, _, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(time.Hour), now); !errors.Is(err, ErrOutstandingCap) {
		t.Fatalf("the cap must bite, got %v", err)
	}

	// Spending one frees a slot: the cap bounds UNSPENT credentials, not devices ever enrolled. Getting this
	// wrong would make a tenant unable to enrol its 201st machine, forever.
	if _, err := s.Consume(secrets[0], "tenant_a", "laptop-01", now); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, _, err := s.Issue(policy, "tenant_a", "", "", "adm_alice", "", now.Add(time.Hour), now); err != nil {
		t.Fatalf("spending a token must free a slot: %v", err)
	}

	// So does another tenant: the cap is per tenant, not global.
	if _, _, err := s.Issue(policy, "tenant_b", "", "", "adm_bob", "", now.Add(time.Hour), now); err != nil {
		t.Fatalf("another tenant must not be blocked by this one's cap: %v", err)
	}
}

// The secret must not be recoverable from anything the store keeps or shows, or a leak of Edge state — or a
// Console screenshot — hands over working credentials.
func TestTheSecretIsNeverRetrievableFromTheStore(t *testing.T) {
	s := NewStore()
	tok, secret := issue(t, s, 72*time.Hour)
	if strings.Contains(tok.Hash, secret) || tok.Hash == secret {
		t.Fatalf("the stored hash must not be the secret")
	}
	for _, listed := range s.List("tenant_a") {
		if strings.Contains(listed.Label+listed.ID+listed.Hash+listed.IssuedBy, secret) {
			t.Fatalf("the secret leaked into a listed record")
		}
	}
}

// Being spent has to survive a restart. If it did not, a copied installer config would work again after any Edge
// bounce, and "one-time" would mean "once per uptime".
func TestSpentAndRevokedStateSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolment_tokens.json")
	now := testNow()

	first := NewStore()
	first.SetStateFile(path)
	_, spent, err := first.Issue(DefaultPolicy(), "tenant_a", "", "spent", "adm_alice", "", now.Add(72*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	killed, unusedSecret, err := first.Issue(DefaultPolicy(), "tenant_a", "", "revoked", "adm_alice", "", now.Add(72*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	fresh, freshSecret, err := first.Issue(DefaultPolicy(), "tenant_a", "", "fresh", "adm_alice", "", now.Add(72*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := first.Consume(spent, "tenant_a", "laptop-01", now); err != nil {
		t.Fatalf("consume: %v", err)
	}
	first.Revoke(killed.ID, "adm_alice", now)

	reborn := NewStore()
	reborn.SetStateFile(path)

	if _, err := reborn.Consume(spent, "tenant_a", "laptop-02", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("a spent token must stay spent across a restart, got %v", err)
	}
	if _, err := reborn.Consume(unusedSecret, "tenant_a", "laptop-02", now); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("a revoked token must stay revoked across a restart, got %v", err)
	}
	if _, err := reborn.Consume(freshSecret, "tenant_a", "laptop-03", now); err != nil {
		t.Fatalf("an untouched token must still work after a restart: %v", err)
	}
	if got := len(reborn.List("tenant_a")); got != 3 {
		t.Fatalf("the records must survive too, got %d", got)
	}
	_ = fresh
}

// A backlog of unused long-lived tokens is the failure mode a caller-chosen lifetime introduces. It is invisible
// unless counted and surfaced, so both are part of the store rather than left to the UI.
func TestOutstandingAndExpiringSurfaceTheBacklog(t *testing.T) {
	s := NewStore()
	now := testNow()
	if _, _, err := s.Issue(DefaultPolicy(), "tenant_a", "", "soon", "adm_alice", "", now.Add(6*time.Hour), now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := s.Issue(DefaultPolicy(), "tenant_a", "", "later", "adm_alice", "", now.Add(20*24*time.Hour), now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, spent, _ := s.Issue(DefaultPolicy(), "tenant_a", "", "spent", "adm_alice", "", now.Add(6*time.Hour), now)
	s.Consume(spent, "tenant_a", "laptop-01", now)

	if got := s.Outstanding("tenant_a", now); got != 2 {
		t.Fatalf("a spent token is not outstanding: got %d, want 2", got)
	}
	soon := s.ExpiringWithin("tenant_a", 24*time.Hour, now)
	if len(soon) != 1 || soon[0].Label != "soon" {
		t.Fatalf("expected only the token lapsing inside the window, got %+v", soon)
	}
	// Once everything has lapsed, nothing is outstanding — an expired token is not a backlog item.
	if got := s.Outstanding("tenant_a", now.Add(30*24*time.Hour)); got != 0 {
		t.Fatalf("expired tokens must not count as outstanding, got %d", got)
	}
}

func TestIssueRequiresATenantAndAnIssuingAdmin(t *testing.T) {
	s := NewStore()
	now := testNow()
	if _, _, err := s.Issue(DefaultPolicy(), "", "", "", "adm_alice", "", now.Add(time.Hour), now); err == nil {
		t.Fatalf("a token with no tenant must be refused")
	}
	if _, _, err := s.Issue(DefaultPolicy(), "tenant_a", "", "", "  ", "", now.Add(time.Hour), now); err == nil {
		t.Fatalf("a token with no issuing admin must be refused — attribution is why the record exists")
	}
}

// Documents the limit of THIS store, and therefore why the Postgres-backed authority exists.
//
// Two Store values sharing one file are what two Edges sharing one blob look like: each loads the file at boot
// and mutates its own map, so a spend on one is invisible to the other and the same token enrols twice. That is
// not a bug in the persister — it is what snapshot persistence means — but it is fatal for a credential whose
// entire value is being one-time, so a deployment with more than one Edge must not use this backend.
//
// The assertion is the CURRENT behaviour. If it ever starts failing, this store has learned to coordinate and
// this test should become the opposite claim rather than being deleted.
func TestTwoStoresSharingOneFileBothSpendTheSameToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolment_tokens.json")
	now := testNow()

	edgeA := NewStore()
	edgeA.SetStateFile(path)
	tok, secret, err := edgeA.Issue(DefaultPolicy(), "tenant_a", "", "", "adm_alice", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The second Edge starts and reads the file — the token is there, unspent, which is correct so far.
	edgeB := NewStore()
	edgeB.SetStateFile(path)

	if _, err := edgeA.Consume(secret, "tenant_a", "laptop-01", now); err != nil {
		t.Fatalf("the first Edge must be able to spend it: %v", err)
	}
	_, err = edgeB.Consume(secret, "tenant_a", "laptop-02", now)
	if err == nil {
		t.Log("OBSERVED: a second Edge spent an already-spent token — one-time holds only within one Edge, " +
			"which is why -enrolment-token-store=postgres exists for multi-Edge deployments")
		return
	}
	t.Fatalf("this store has started coordinating across instances (%v) — update this test to assert that "+
		"instead of the snapshot limitation, and revisit whether the Postgres backend is still required", err)
	_ = tok
}
