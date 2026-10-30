package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/migrations"
)

func TestAuthResultPrunerCleansIdleTenantsInBoundedBatches(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the PostgreSQL retention check")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ddl, err := os.ReadFile("../../migrations/053_auth_flow_results.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations.SplitSQLStatements(string(ddl)) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	tenant := fmt.Sprintf("retention_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM auth_flow_results WHERE tenant_id=$1", tenant)
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 514; i++ {
		expires := now.Add(-time.Second).Unix()
		if i == 513 {
			expires = now.Add(time.Hour).Unix()
		}
		_, err = db.Exec(`INSERT INTO auth_flow_results (request_id,tenant_id,device_id,os_principal,os_session,result,final_at,expires_at) VALUES ($1,$2,'device','principal','session','resumed',$3,$4)`, authResultProcessID(tenant, fmt.Sprint(i)), tenant, now.Add(-time.Minute).Unix(), expires)
		if err != nil {
			t.Fatal(err)
		}
	}
	store := newPostgresAuthResultStore(db)
	store.clock = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.pruneExpired(ctx); err == nil {
		t.Fatal("cancelled maintenance wrote")
	}
	for i := 0; i < 10; i++ {
		n, err := store.pruneExpired(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n < 0 || n > 512 {
			t.Fatal("unbounded result sweep", n)
		}
		if n < 512 {
			break
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM auth_flow_results WHERE tenant_id=$1", tenant).Scan(&count); err != nil || count != 1 {
		t.Fatal("idle expired rows retained or active row deleted", count, err)
	}
}
