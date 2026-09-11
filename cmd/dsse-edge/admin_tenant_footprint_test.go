package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
)

// The footprint is what an erasure claim rests on, so its own honesty is the thing under test: a store that
// could not be counted must never read as empty, and every store this node cannot reach must be NAMED.
func TestFootprintNeverPresentsAnUnknownAsClean(t *testing.T) {
	clean := adminTenantFootprint{Stores: []adminTenantFootprintRow{{Store: "a", Count: 0}, {Store: "b", Count: 0}}}
	if !clean.Clean() {
		t.Fatal("all-zero must be clean")
	}
	held := adminTenantFootprint{Stores: []adminTenantFootprintRow{{Store: "a", Count: 0}, {Store: "b", Count: 3}}}
	if held.Clean() {
		t.Fatal("a store holding rows is not clean")
	}
	failed := adminTenantFootprint{Stores: []adminTenantFootprintRow{{Store: "a", Count: 0}, {Store: "b", Count: -1, Error: "connection refused"}}}
	if failed.Clean() {
		t.Fatal("a store that FAILED to count must never be reported clean — an unknown is not an absence")
	}
}

// Every store this node cannot reach has to be named. A footprint that omits them reads as "nothing there"
// for exactly the store that may still hold everything.
func TestFootprintDeclaresWhatItDidNotCount(t *testing.T) {
	f := countAdminTenantFootprint(context.Background(), "test-node", "tenant_x", nil, nil, nil, nil, nil, nil, nil, adminTenantExtraStores{}, time.Now())
	if len(f.NotCounted) == 0 {
		t.Fatal("a footprint with no stores wired must say so, not return an empty clean report")
	}
	want := []string{"clickhouse", "object storage", "payload", "other Edges", "postgres", "log_files", "admin_accounts", "enrolled_identities"}
	joined := ""
	for _, entry := range f.NotCounted {
		joined += entry + "\n"
	}
	for _, needle := range want {
		if !strings.Contains(joined, needle) {
			t.Fatalf("not_counted must name %q:\n%s", needle, joined)
		}
	}
	if f.Node != "test-node" {
		t.Fatalf("node = %q — a footprint that does not say WHICH node it counted invites reading one node's zero as the fleet's", f.Node)
	}
}

// The stores this node CAN reach are counted, and a tenant's directory that was never written is a real zero
// rather than an error.
func TestFootprintCountsAccountsIdentitiesAndLogFiles(t *testing.T) {
	credentials := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()
	if _, err := credentials.Invite("a@corp.example", "tenant_x", "adm_a", []string{"admin"}, now); err != nil {
		t.Fatalf("invite: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("device-1", "tenant_x", "", now.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	dir := t.TempDir()
	tenantLogs := filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_x"))
	if err := os.MkdirAll(tenantLogs, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tenantLogs, "access.log.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}

	f := countAdminTenantFootprint(context.Background(), "node", "tenant_x", nil, writer, credentials, ledger, nil, nil, nil, adminTenantExtraStores{}, now)
	got := map[string]int64{}
	for _, row := range f.Stores {
		got[row.Store] = row.Count
	}
	if got["admin_accounts"] != 1 || got["enrolled_identities"] != 1 || got["log_files"] != 1 {
		t.Fatalf("counts = %v, want one of each", got)
	}
	if f.Clean() {
		t.Fatal("a tenant with an account, a device and a log file is not clean")
	}

	// A tenant this node never served has no directory at all, and that is a genuine zero — not an error, and
	// not something to report as unknown.
	empty := countAdminTenantFootprint(context.Background(), "node", "tenant_never_here", nil, writer, credentials, ledger, nil, nil, nil, adminTenantExtraStores{}, now)
	if !empty.Clean() {
		t.Fatalf("a tenant this node never served must count clean, got %+v", empty.Stores)
	}
}
