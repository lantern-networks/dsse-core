package main

import (
	"database/sql"
	"os"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	_ "github.com/lib/pq"
)

// TestCPStateBlobPersisterResolver locks in the flag-value → Persister mapping: "" = none, a path = file,
// "postgres" = shared cp_state_blobs (and errors without a DB). No database needed.
func TestCPStateBlobPersisterResolver(t *testing.T) {
	// empty → nil (in-memory only)
	if p, err := cpStateBlobPersister("", nil, "policy_rules"); err != nil || p != nil {
		t.Fatalf(`empty: got (%v, %v), want (nil, nil)`, p, err)
	}
	// a path → FilePersister at that path
	p, err := cpStateBlobPersister("/cp-state/policy_rules.json", nil, "policy_rules")
	if err != nil {
		t.Fatalf("path: unexpected err %v", err)
	}
	// Wrapped, since 2026-08-15, so that saving refreshes this node's ownership stamp on the path: per-node
	// state on a shared mount has cost a re-usable device identity once and a silent config-distribution
	// freeze once, and the stamp is what lets the next occurrence name the other node instead of presenting
	// as an Edge that is mysteriously behind.
	owned, ok := p.(blobstore.OwnedFilePersister)
	if !ok || owned.File.Path != "/cp-state/policy_rules.json" {
		t.Fatalf("path: got %#v, want OwnedFilePersister over /cp-state/policy_rules.json", p)
	}
	if owned.NodeID == "" {
		t.Fatal("the persister carries no node id, so its stamp would name nobody")
	}
	// "postgres" without a DB → error (don't silently fall back to a file)
	if _, err := cpStateBlobPersister("postgres", nil, "policy_rules"); err == nil {
		t.Fatal("postgres without a DB must error")
	}
	// "postgres" with a DB → a postgresBlobPersister keyed by the store key
	db, _ := sql.Open("postgres", "") // no connection needed for this check
	defer db.Close()
	p, err = cpStateBlobPersister("postgres", db, "policy_rules")
	if err != nil {
		t.Fatalf("postgres+db: unexpected err %v", err)
	}
	pg, ok := p.(postgresBlobPersister)
	if !ok || pg.key != "policy_rules" || pg.db != db {
		t.Fatalf("postgres+db: got %#v, want postgresBlobPersister{key:policy_rules}", p)
	}
}

// TestPostgresBlobPersisterRoundTrip proves save→load→overwrite through a real Postgres (gated on a DSN).
func TestPostgresBlobPersisterRoundTrip(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := newCPStateBlobDB(dsn, "migrations", true)
	if err != nil {
		t.Fatalf("open cp-state blob db: %v", err)
	}
	defer db.Close()
	key := "test_blob_roundtrip"
	_, _ = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	p := postgresBlobPersister{db: db, key: key}

	// absent → (nil, nil)
	if data, err := p.Load(); err != nil || data != nil {
		t.Fatalf("absent: got (%v, %v), want (nil, nil)", data, err)
	}
	// save → load
	if err := p.Save([]byte(`{"seq":1}`)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if data, err := p.Load(); err != nil || string(data) != `{"seq":1}` {
		t.Fatalf("load: got (%q, %v), want {\"seq\":1}", data, err)
	}
	// overwrite (upsert)
	if err := p.Save([]byte(`{"seq":2}`)); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if data, _ := p.Load(); string(data) != `{"seq":2}` {
		t.Fatalf("overwrite load: got %q, want {\"seq\":2}", data)
	}
	_, _ = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
}
