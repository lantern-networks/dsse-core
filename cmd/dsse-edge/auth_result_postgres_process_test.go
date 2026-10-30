package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/migrations"
	_ "github.com/lib/pq"
)

func authResultProcessID(tenant, suffix string) string {
	sum := sha256.Sum256([]byte(tenant + ":" + suffix))
	return fmt.Sprintf("%x", sum[:16])
}

// Separate CP processes write and read independent result rows in real SQL.
func TestAuthResultLedgerAcrossPostgresProcesses(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the real PostgreSQL process check")
	}
	tenant := os.Getenv("DSSE_AUTH_RESULT_PROCESS_TENANT")
	if tenant != "" {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		ledger := newPostgresAuthResultStore(db)
		r := authResultFixture(time.Now().UTC().Truncate(time.Second))
		r.TenantID = tenant
		switch os.Getenv("DSSE_AUTH_RESULT_PROCESS_STAGE") {
		case "write-a":
			r.RequestID = authResultProcessID(tenant, "a")
			if err := ledger.Record(r); err != nil {
				t.Fatal(err)
			}
		case "write-b":
			r.RequestID = authResultProcessID(tenant, "b")
			r.Result = "not_resumed"
			if err := ledger.Record(r); err != nil {
				t.Fatal(err)
			}
		case "read-c":
			r.RequestID = authResultProcessID(tenant, "c")
			if got, err := ledger.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "resumed" {
				t.Fatalf("other process lookup = %q, %v", got, err)
			}
		default:
			t.Fatal("unknown process stage")
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
	ddl, err := os.ReadFile("../../migrations/053_auth_flow_results.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations.SplitSQLStatements(string(ddl)) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	tenant = fmt.Sprintf("test_auth_flow_results_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM auth_flow_results WHERE tenant_id=$1 OR tenant_id=$2", tenant, tenant+"_other")
	child := func(stage string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestAuthResultLedgerAcrossPostgresProcesses$", "-test.v")
		cmd.Env = append(os.Environ(), "DSSE_AUTH_RESULT_PROCESS_TENANT="+tenant, "DSSE_AUTH_RESULT_PROCESS_STAGE="+stage)
		return cmd
	}
	// Both writers begin independently against the same tenant's empty set.
	writers := []*exec.Cmd{child("write-a"), child("write-b")}
	outputs := []*bytes.Buffer{{}, {}}
	for i, cmd := range writers {
		cmd.Stdout, cmd.Stderr = outputs[i], outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, cmd := range writers {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d failed: %v; %s", i, err, outputs[i])
		}
	}
	ledger := newPostgresAuthResultStore(db)
	r := authResultFixture(time.Now().UTC().Truncate(time.Second))
	r.TenantID = tenant
	r.RequestID = authResultProcessID(tenant, "a")
	if got, err := ledger.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "resumed" {
		t.Fatalf("standby process lookup = %q, %v", got, err)
	}
	if got, err := ledger.Lookup(r.RequestID, r.TenantID, "other-device", r.Principal, r.Session); err != nil || got != "" {
		t.Fatalf("different device lookup = %q, %v", got, err)
	}
	r.RequestID = authResultProcessID(tenant, "b")
	if got, err := ledger.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != "not_resumed" {
		t.Fatalf("second writer result = %q, %v", got, err)
	}
	r.RequestID = authResultProcessID(tenant, "c")
	if err := ledger.Record(r); err != nil {
		t.Fatal(err)
	}
	if output, err := child("read-c").CombinedOutput(); err != nil {
		t.Fatalf("other process read failed: %v; %s", err, output)
	}
	ledger.limit = 3
	r.RequestID = authResultProcessID(tenant, "d")
	if err := ledger.Record(r); err == nil || !strings.Contains(err.Error(), "tenant ledger is full") {
		t.Fatalf("tenant capacity result = %v", err)
	}
	r.TenantID = tenant + "_other"
	r.RequestID = authResultProcessID(tenant, "other")
	if err := ledger.Record(r); err != nil {
		t.Fatalf("one tenant exhausted another's result capacity: %v", err)
	}
}
