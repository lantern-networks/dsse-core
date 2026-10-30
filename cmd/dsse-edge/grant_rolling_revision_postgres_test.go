package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/migrations"
)

func TestPostgresGrantRevisionFallsBackBeforeMigration(t *testing.T) {
	dsn := os.Getenv("DSSE_ROLLING_TEST_DSN")
	if dsn == "" {
		t.Skip("DSSE_ROLLING_TEST_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE cp_state_blobs (store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("test requires a fresh database:", err)
	}
	defer db.Exec(`DROP TABLE IF EXISTS cp_state_blobs`)
	store := grantstore.NewStore()
	if err := store.SetPersister(grantstore.NewCachedRollingPersister(postgresGrantPair{db: db})); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.Mint(grantstore.Grant{GrantID: "legacy-schema", TenantID: "tenant", UserID: "user", IdPID: "idp"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListChecked("tenant"); err != nil || len(rows) != 1 {
		t.Fatalf("older schema full-read fallback: rows=%d err=%v", len(rows), err)
	}
}

// Run only against a disposable database: the production grant keys and a
// migration trigger are created and removed by this test.
func TestPostgresGrantRevisionSeesReleasedWriterAndRecreation(t *testing.T) {
	dsn := os.Getenv("DSSE_ROLLING_TEST_DSN")
	if dsn == "" {
		t.Skip("DSSE_ROLLING_TEST_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE cp_state_blobs (store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("test requires a fresh database:", err)
	}
	defer func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS cp_state_blobs`)
		_, _ = db.Exec(`DROP FUNCTION IF EXISTS dsse_stamp_grant_blob_revision()`)
		_, _ = db.Exec(`DROP SEQUENCE IF EXISTS dsse_grant_blob_revision_seq`)
	}()
	ddl, err := os.ReadFile("../../migrations/056_grant_blob_revision.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations.SplitSQLStatements(string(ddl)) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("apply grant revision migration: %v", err)
		}
	}
	pair := postgresGrantPair{db: db}
	store := grantstore.NewStore()
	if err := store.SetPersister(grantstore.NewCachedRollingPersister(pair)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant := grantstore.Grant{GrantID: "shared", TenantID: "tenant", UserID: "user", IdPID: "idp",
		Scope: "app:22", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, err := store.Mint(grant, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	before, err := pair.GrantPairRevision(t.Context())
	if err != nil || !before.LegacyPresent || !before.EvidencePresent || before.Legacy <= 0 || before.Evidence <= 0 {
		t.Fatalf("revision after mint: %+v err=%v", before, err)
	}
	legacy, _, err := pair.LoadGrantPair(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var rows map[string]map[string]any
	if err := json.Unmarshal(legacy, &rows); err != nil {
		t.Fatal(err)
	}
	rows["shared"]["revoked"] = true
	revoked, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	// This SQL has the shape of the released map-only writer. It does not know
	// about the new revision column or the evidence sidecar.
	if _, err := db.Exec(`UPDATE cp_state_blobs SET payload=$1,updated_at=now() WHERE store_key='grants'`, revoked); err != nil {
		t.Fatal(err)
	}
	after, err := pair.GrantPairRevision(t.Context())
	if err != nil || after.Legacy == before.Legacy || after.Evidence != before.Evidence {
		t.Fatalf("released write did not stamp only the legacy key: before=%+v after=%+v err=%v", before, after, err)
	}
	if store.Valid("shared", now) {
		t.Fatal("cached authority missed released writer's revocation")
	}
	if _, err := db.Exec(`DELETE FROM cp_state_blobs WHERE store_key='grants'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cp_state_blobs(store_key,payload) VALUES ('grants',$1)`, revoked); err != nil {
		t.Fatal(err)
	}
	recreated, err := pair.GrantPairRevision(t.Context())
	if err != nil || recreated.Legacy == after.Legacy || !recreated.LegacyPresent {
		t.Fatalf("delete/reinsert reused a grant revision: before=%+v after=%+v err=%v", after, recreated, err)
	}
}
