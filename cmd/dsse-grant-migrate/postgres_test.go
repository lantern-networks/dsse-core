package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/grantstore"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresRollbackOffline(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_GRANT_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated local Postgres not supplied")
	}
	t.Setenv("DSSE_GRANT_MIGRATION_DSN", dsn)
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal("open database")
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TABLE cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		t.Fatal("create isolated table", e)
	}
	defer db.Exec(`DROP TABLE cp_state_blobs`)
	raw := []byte(`{"schema_version":3,"grants":{"g":{"grant_id":"g","tenant_id":"t","issued_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-15T01:00:00Z"}}}`)
	if _, e = db.Exec(`INSERT INTO cp_state_blobs(store_key,payload) VALUES ('grants',$1)`, raw); e != nil {
		t.Fatal(e)
	}
	var status bytes.Buffer
	if e = run([]string{"--postgres"}, &status); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(t.TempDir(), "original.json")
	if e = run([]string{"--postgres", "--apply", "--writers-stopped", "--expect-sha256", digest(raw), "--backup", backup}, &status); e != nil {
		t.Fatal(e)
	}
	var stored []byte
	if e = db.QueryRow(`SELECT payload FROM cp_state_blobs WHERE store_key='grants'`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	var old map[string]grantstore.Grant
	if json.Unmarshal(stored, &old) != nil || len(old) != 1 || !old["g"].Revoked {
		t.Fatal("legacy load/revocation failed")
	}
	copy, e := os.ReadFile(backup)
	if e != nil || !bytes.Equal(copy, raw) {
		t.Fatal("backup differs")
	}
	// Stale dry-run SHA must not overwrite a later authority state.
	if e = run([]string{"--postgres", "--apply", "--writers-stopped", "--expect-sha256", digest(raw), "--backup", filepath.Join(t.TempDir(), "stale.json")}, &status); e == nil {
		t.Fatal("stale source overwritten")
	}
}
