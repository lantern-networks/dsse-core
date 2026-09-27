package main

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

// Requires a real database, because the property under test IS the database's: a conditional UPDATE deciding a
// race. An in-process fake would only test the fake.
func openEnrolmentTokenDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("ENROLMENT_TOKEN_E2E_DSN")
	if dsn == "" {
		t.Skip("ENROLMENT_TOKEN_E2E_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	selected, err := selectPostgresComponentMigrations(migrations, "enrolment tokens", postgresMigrationEnrolmentTokens, postgresMigrationEnrolmentTokenIssuerLabel)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := migrationstore.Apply(t.Context(), db, selected); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM enrolment_tokens WHERE tenant_id LIKE 'tenant_test_%'`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	return db
}

// The reason this backend exists. Sixteen goroutines race to spend one token, as two Edges would with a copied
// installer config; exactly one may win. The in-memory store passes this within one process and CANNOT pass it
// across two, which is why a multi-Edge deployment has to use this one.
func TestPostgresEnrolmentTokenIsSpentExactlyOnceUnderRace(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()
	tok, secret, err := s.Issue(enrolltoken.DefaultPolicy(), "tenant_test_race", "", "race", "adm_alice", "",
		now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.Verify(secret, "tenant_test_race", now); err != nil {
		t.Fatalf("a fresh token must verify: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Spend(tok.ID, "tenant_test_race", "racer", time.Now().UTC()); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one spend may succeed, got %d", wins)
	}
	if _, err := s.Verify(secret, "tenant_test_race", time.Now().UTC()); !errors.Is(err, enrolltoken.ErrTokenUsed) {
		t.Fatalf("after the race the token must read as used, got %v", err)
	}
}

// A second store instance is a stand-in for a second Edge: separate process, same database. The blob-backed store
// would fail this, and failing it silently is exactly the bug this replaces.
func TestASecondEdgeSeesTheTokenAlreadySpent(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	edgeA := newPostgresEnrolmentTokenStore(db)
	edgeB := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()

	tok, secret, err := edgeA.Issue(enrolltoken.DefaultPolicy(), "tenant_test_two_edges", "", "", "adm_alice", "",
		now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := edgeA.Spend(tok.ID, "tenant_test_two_edges", "laptop-01", now); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	if _, err := edgeB.Verify(secret, "tenant_test_two_edges", now); !errors.Is(err, enrolltoken.ErrTokenUsed) {
		t.Fatalf("the other Edge must see it spent, got %v", err)
	}
	if _, err := edgeB.Spend(tok.ID, "tenant_test_two_edges", "laptop-02", now); !errors.Is(err, enrolltoken.ErrTokenUsed) {
		t.Fatalf("the other Edge must refuse to spend it, got %v", err)
	}
}

// The two backends have to answer the same questions the same way, or migrating between them changes behaviour
// an operator did not ask to change.
func TestPostgresMatchesTheInMemoryStoreOnRefusals(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	pg := newPostgresEnrolmentTokenStore(db)
	mem := enrolltoken.NewStore()
	now := time.Now().UTC()

	cases := []struct {
		name  string
		setup func(a enrolltoken.Authority) string // returns the secret to present
		want  error
	}{
		{"unknown", func(a enrolltoken.Authority) string { return "never-issued" }, enrolltoken.ErrUnknownToken},
		{"used", func(a enrolltoken.Authority) string {
			tok, sec, _ := a.Issue(enrolltoken.DefaultPolicy(), "tenant_test_parity", "", "", "adm_a", "", now.Add(time.Hour), now)
			a.Spend(tok.ID, "tenant_test_parity", "d", now)
			return sec
		}, enrolltoken.ErrTokenUsed},
		{"revoked", func(a enrolltoken.Authority) string {
			tok, sec, _ := a.Issue(enrolltoken.DefaultPolicy(), "tenant_test_parity", "", "", "adm_a", "", now.Add(time.Hour), now)
			a.Revoke(tok.ID, "adm_a", now)
			return sec
		}, enrolltoken.ErrTokenRevoked},
		{"expired", func(a enrolltoken.Authority) string {
			_, sec, _ := a.Issue(enrolltoken.DefaultPolicy(), "tenant_test_parity", "", "", "adm_a", "", now.Add(time.Second), now)
			return sec
		}, enrolltoken.ErrTokenExpired},
		{"wrong tenant", func(a enrolltoken.Authority) string {
			_, sec, _ := a.Issue(enrolltoken.DefaultPolicy(), "tenant_test_parity", "", "", "adm_a", "", now.Add(time.Hour), now)
			return sec
		}, enrolltoken.ErrWrongTenant},
	}
	for _, c := range cases {
		for _, backend := range []struct {
			label string
			a     enrolltoken.Authority
		}{{"postgres", pg}, {"memory", mem}} {
			secret := c.setup(backend.a)
			at, tenant := now, "tenant_test_parity"
			if c.name == "expired" {
				at = now.Add(time.Minute)
			}
			if c.name == "wrong tenant" {
				tenant = "tenant_test_other"
			}
			if err := func() error { _, e := backend.a.Verify(secret, tenant, at); return e }(); !errors.Is(err, c.want) {
				t.Errorf("%s/%s: want %v, got %v", backend.label, c.name, c.want, err)
			}
		}
	}
}

// Outstanding counts UNSPENT tokens and drives the issuance cap, so a read failure must not read as zero — that
// would let issuance sail past the cap exactly when the database is unhappy.
func TestPostgresOutstandingCountsOnlyUnspentTokens(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()
	const tenant = "tenant_test_outstanding"

	tokA, _, _ := s.Issue(enrolltoken.DefaultPolicy(), tenant, "", "waiting", "adm_a", "", now.Add(2*time.Hour), now)
	tokB, _, _ := s.Issue(enrolltoken.DefaultPolicy(), tenant, "", "spent", "adm_a", "", now.Add(2*time.Hour), now)
	tokC, _, _ := s.Issue(enrolltoken.DefaultPolicy(), tenant, "", "revoked", "adm_a", "", now.Add(2*time.Hour), now)
	s.Spend(tokB.ID, tenant, "d", now)
	s.Revoke(tokC.ID, "adm_a", now)

	if got := s.Outstanding(tenant, now); got != 1 {
		t.Fatalf("only the unspent, unrevoked, unexpired token counts: got %d, want 1", got)
	}
	if got := s.Outstanding(tenant, now.Add(3*time.Hour)); got != 0 {
		t.Fatalf("an expired token is not outstanding: got %d", got)
	}
	soon := s.ExpiringWithin(tenant, 3*time.Hour, now)
	if len(soon) != 1 || soon[0].ID != tokA.ID {
		t.Fatalf("expected only the waiting token in the window, got %+v", soon)
	}
}
