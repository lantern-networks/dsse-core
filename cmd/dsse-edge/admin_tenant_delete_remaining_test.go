package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
)

// ★ "deleted: true" IS HALF THE ANSWER (2026-08-17). Deleting an organization removes it from the registry and
// takes its accounts, tokens and sessions with it. It does NOT erase what the organization produced: its audit
// log partition and its rows in the durable outbox stay on every node that held them. The response listed only
// what it removed, so five probe organizations deleted earlier that night were still on disk — partitions and
// 38 outbox rows — hours later, with nothing having said so.
//
// The delete is correct. The claim was incomplete, which is the failure mode this codebase keeps finding: a
// true statement that a reader completes wrongly. This pins the shape of the fuller answer.
func TestDeletingAnOrganizationReportsWhatItLeavesBehind(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	// An organization that produced something: one audit partition on this node.
	partition := filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_left"))
	if err := os.MkdirAll(partition, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(partition, "audit.log.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	footprint := countAdminTenantFootprint(context.Background(), "node", "tenant_left", nil, writer,
		newLocalAdminCredentialStore("Lantern DSSE"), enrolledinventory.NewLedger(), nil, nil, nil, adminTenantExtraStores{}, time.Now())
	if footprint.Clean() {
		t.Fatal("the organization left an audit partition behind, so the footprint must not be clean — " +
			"a delete response built on this would tell an operator everything was gone")
	}

	// And an organization that produced nothing reports clean, so the note is not attached to every delete.
	empty := countAdminTenantFootprint(context.Background(), "node", "tenant_never_here", nil, writer,
		newLocalAdminCredentialStore("Lantern DSSE"), enrolledinventory.NewLedger(), nil, nil, nil, adminTenantExtraStores{}, time.Now())
	if !empty.Clean() {
		t.Fatalf("nothing was ever here, so the footprint is clean: %+v", empty.Stores)
	}
}
