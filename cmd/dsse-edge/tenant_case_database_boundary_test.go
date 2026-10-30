package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// Each test gets a schema rather than changing the shared PostgreSQL test DB.
func tenantCaseReviewDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	schema := fmt.Sprintf("tenant_case_review_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = base.Exec("DROP SCHEMA " + schema + " CASCADE") })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func applyTenantCaseReviewMigrations(t *testing.T, db *sql.DB, versions ...string) {
	t.Helper()
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := migrationstore.SelectVersions(all, versions...)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(context.Background(), db, selected); err != nil {
		t.Fatal(err)
	}
}

func TestPKIHistoryGuardSeparatesCaseDistinctTenants(t *testing.T) {
	db := tenantCaseReviewDB(t)
	if _, err := db.Exec(`CREATE TABLE cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	applyTenantCaseReviewMigrations(t, db, "047")
	before := []byte(`[{"tenant_id":"Acme","retired_anchor_sha256":["aaaa"]},{"tenant_id":"acme","retired_anchor_sha256":["bbbb"]}]`)
	if _, err := db.Exec(`INSERT INTO cp_state_blobs(store_key,payload) VALUES ('tenant_device_authorities',$1)`, before); err != nil {
		t.Fatal(err)
	}
	// The first candidate contains both fingerprints, but it belongs to acme.
	// Acme's own retirement history was removed and must be rejected.
	bad := []byte(`[{"tenant_id":"acme","retired_anchor_sha256":["aaaa","bbbb"]},{"tenant_id":"Acme","retired_anchor_sha256":[]}]`)
	if _, err := db.Exec(`UPDATE cp_state_blobs SET payload=$1 WHERE store_key='tenant_device_authorities'`, bad); err == nil || !strings.Contains(err.Error(), "pki_history_regression") {
		t.Fatalf("case-distinct history regression was accepted: %v", err)
	}
	var held []byte
	if err := db.QueryRow(`SELECT payload FROM cp_state_blobs WHERE store_key='tenant_device_authorities'`).Scan(&held); err != nil || string(held) != string(before) {
		t.Fatalf("failed history write altered original: %v", err)
	}
	// Reordering exact rows without changing either tenant's history is valid.
	valid := []byte(`[{"tenant_id":"acme","retired_anchor_sha256":["bbbb"]},{"tenant_id":"Acme","retired_anchor_sha256":["aaaa"]}]`)
	if _, err := db.Exec(`UPDATE cp_state_blobs SET payload=$1 WHERE store_key='tenant_device_authorities'`, valid); err != nil {
		t.Fatalf("exact per-tenant history was refused: %v", err)
	}
}

func TestEnrollmentClaimsSeparateCaseDistinctTenants(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "035", "036", "037")
	claims := postgresEnrolledIdentityClaims{db: db, nodeID: "review-issuer"}
	for _, tenant := range []string{"Acme", "acme"} {
		ok, err := claims.ClaimIdentity(context.Background(), tenant, "device-1", 0)
		if err != nil || !ok {
			t.Fatalf("claim %q failed: ok=%v err=%v", tenant, ok, err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM enrolled_identity_claims WHERE identity='device-1'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("case-distinct claim count=%d err=%v, want 2", count, err)
	}
	if err := claims.ReleaseIdentity(context.Background(), "Acme", "device-1", 0); err != nil {
		t.Fatal(err)
	}
	var remaining string
	if err := db.QueryRow(`SELECT tenant_id FROM enrolled_identity_claims WHERE identity='device-1'`).Scan(&remaining); err != nil || remaining != "acme" {
		t.Fatalf("release removed wrong claim: tenant=%q err=%v", remaining, err)
	}
}

func TestEnrollmentClaimMigrationPreservesCaseDistinctRows(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "035")
	if _, err := db.Exec(`INSERT INTO enrolled_identity_claims(tenant_id,identity,reenrolment_grant,claimed_at,claimed_by) VALUES
		('Acme','device-1',0,now(),'one'),('acme','device-1',0,now(),'two')`); err != nil {
		t.Fatal(err)
	}
	applyTenantCaseReviewMigrations(t, db, "037")
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM enrolled_identity_claims WHERE identity='device-1'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("migration collapsed case-distinct claims: count=%d err=%v", count, err)
	}
}
