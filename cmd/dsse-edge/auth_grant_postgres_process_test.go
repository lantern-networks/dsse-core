package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// The same signed start request can reach a restarted or different Portal.
// Two processes must race for one grant ID in the real shared SQL authority;
// only the winner may issue a bearer grant.
func TestAuthGrantSingleIssuanceAcrossPostgresProcesses(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the real PostgreSQL process check")
	}
	key := os.Getenv("DSSE_AUTH_GRANT_PROCESS_KEY")
	if key != "" {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		store := grantstore.NewStore()
		if err := store.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
			t.Fatal(err)
		}
		signer := newDeviceBindingSignerFromSecret("test-only-shared-deployment-key")
		id := signer.grantIDForRequest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if id == "" || id == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
			t.Fatal("grant ID must be opaque and distinct from the browser request ID")
		}
		_, err = store.Mint(grantstore.Grant{GrantID: id, TenantID: "tenant"}, time.Hour, time.Now())
		switch {
		case err == nil:
			fmt.Println("MINTED")
		case errors.Is(err, grantstore.ErrConflict):
			fmt.Println("CONFLICT")
		default:
			t.Fatal(err)
		}
		return
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (
		store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	key = fmt.Sprintf("test_auth_grant_once_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	children := []*exec.Cmd{
		exec.Command(os.Args[0], "-test.run=^TestAuthGrantSingleIssuanceAcrossPostgresProcesses$", "-test.v"),
		exec.Command(os.Args[0], "-test.run=^TestAuthGrantSingleIssuanceAcrossPostgresProcesses$", "-test.v"),
	}
	outputs := []*bytes.Buffer{{}, {}}
	for i, cmd := range children {
		cmd.Env = append(os.Environ(), "DSSE_AUTH_GRANT_PROCESS_KEY="+key)
		cmd.Stdout, cmd.Stderr = outputs[i], outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	minted, conflicts := 0, 0
	for i, cmd := range children {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d failed: %v; %s", i, err, outputs[i])
		}
		if strings.Contains(outputs[i].String(), "MINTED") {
			minted++
		}
		if strings.Contains(outputs[i].String(), "CONFLICT") {
			conflicts++
		}
	}
	if minted != 1 || conflicts != 1 {
		t.Fatalf("same request issued %d grants and %d conflicts", minted, conflicts)
	}
	store := grantstore.NewStore()
	if err := store.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListChecked("tenant")
	if err != nil || len(rows) != 1 {
		t.Fatalf("fresh authority read: %d grants, %v", len(rows), err)
	}
}
