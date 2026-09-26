package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

func blobWriterPostgresFixture(t *testing.T) (postgresBlobPersister, *cpLeaderElector, *cpLeaderElector) {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	schema := fmt.Sprintf("distribution_term_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Exec("DROP SCHEMA " + schema + " CASCADE") })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	t.Setenv("POSTGRES_QUEUE_E2E_DSN", u.String())
	a, b := postgresFailureElectors(t)
	db, err := sql.Open("postgres", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = a
	edgeIsControlPlane = true
	t.Cleanup(func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP })
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial leader absent")
	}
	return postgresBlobPersister{db: db, key: "writer_fixture"}, a, b
}
