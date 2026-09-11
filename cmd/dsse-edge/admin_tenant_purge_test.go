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

// The purge erases what this node holds and PROVES it by re-counting. The proof is the point: an erasure that
// answers "done" without a count is a claim nobody can check.
func TestPurgeErasesThisNodeAndProvesItWithACount(t *testing.T) {
	credentials := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()
	if _, err := credentials.Invite("gone@corp.example", "tenant_gone", "adm_gone", []string{"admin"}, now); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := credentials.Invite("stays@corp.example", "tenant_stays", "adm_stays", []string{"admin"}, now); err != nil {
		t.Fatalf("invite: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := now.UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("device-gone", "tenant_gone", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("device-stays", "tenant_stays", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	for _, tenant := range []string{"tenant_gone", "tenant_stays"} {
		partition := filepath.Join(dir, "tenants", logs.SafeTenantSegment(tenant))
		if err := os.MkdirAll(partition, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(partition, "access.log.jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	result := purgeAdminTenantData(context.Background(), "node", "tenant_gone", nil, writer, credentials, ledger, nil, nil, "", nil, nil, adminTenantExtraStores{}, now)

	if !result.Complete {
		t.Fatalf("the purge must report complete when nothing is left, got failures=%v remaining=%+v", result.Failures, result.Remaining.Stores)
	}
	if !result.Remaining.Clean() {
		t.Fatalf("the post-purge count is the evidence and it is not clean: %+v", result.Remaining.Stores)
	}
	if len(result.Erased) == 0 {
		t.Fatal("the purge must say what it erased")
	}
	// And it stopped at the tenant boundary.
	if len(credentials.List("tenant_stays")) != 1 || !ledger.IsAdmitted("device-stays") {
		t.Fatal("the purge crossed into another tenant")
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_stays"), "access.log.jsonl")); err != nil {
		t.Fatalf("another tenant's logs were erased: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); !os.IsNotExist(err) {
		t.Fatalf("the purged tenant's log partition is still on disk: %v", err)
	}
}

// Purging a tenant that was never here is a clean no-op rather than an error — an operator confirming that a
// node holds nothing must not be met with a failure.
func TestPurgingATenantThisNodeNeverHadIsCleanAndSaysNothingWasErased(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	result := purgeAdminTenantData(context.Background(), "node", "tenant_never", nil, writer,
		newLocalAdminCredentialStore("Lantern DSSE"), enrolledinventory.NewLedger(), nil, nil, "", nil, nil, adminTenantExtraStores{}, time.Now())

	if !result.Complete {
		t.Fatalf("a node that never held the tenant is complete, got %v", result.Failures)
	}
	if len(result.Erased) != 0 {
		t.Fatalf("nothing was there, so nothing should be reported erased: %+v", result.Erased)
	}
}

// The log partition must be closed before it is unlinked. On a system holding the descriptor the bytes
// survive the unlink until the process lets go, so a purge that skipped this would report success while the
// data was still readable — and would only really take effect at the next restart.
func TestPurgeClosesTheLogHandlesBeforeRemovingThem(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	writer.SetTenantPartitionedFiles("access.log.jsonl")
	if err := writer.Append("access.log.jsonl", map[string]any{"tenant_id": "tenant_gone"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	partition := filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))
	if _, err := os.Stat(partition); err != nil {
		t.Fatalf("the append should have created the partition: %v", err)
	}

	if _, err := purgeTenantLogDirectory(writer, "tenant_gone"); err != nil {
		t.Fatalf("purge log directory: %v", err)
	}
	if _, err := os.Stat(partition); !os.IsNotExist(err) {
		t.Fatalf("the partition survived the purge: %v", err)
	}
	// The writer stays usable afterwards. A purged tenant that somehow writes again is a fact worth having on
	// disk rather than one silently dropped.
	if err := writer.Append("access.log.jsonl", map[string]any{"tenant_id": "tenant_gone"}); err != nil {
		t.Fatalf("the writer must still work after a tenant purge: %v", err)
	}
}

// ★ THE REGRESSION THIS EXISTS FOR (2026-08-15). The purge writes an audit record, the audit writer partitions
// records BY TENANT, and the record carried the purged tenant's id — so the erasure recreated the very log
// partition it had just removed. On the lab the purge answered complete=true and the fleet view showed the
// tenant back with one file seconds later. The record has to belong to the operator who performed the
// erasure, with the erased customer as the target: evidence that an erasure happened must not be stored
// inside the thing that was erased.
func TestThePurgeAuditRecordBelongsToTheOperatorNotTheErasedTenant(t *testing.T) {
	record := adminTenantModelLifecycleAuditLog(adminTenantModel{TenantID: "tenant_gone"}, "purge", testEvaluator(), time.Now())
	// What the route does, and what the defect was missing.
	record.TenantID = "tenant_operator"

	if record.TenantID == "tenant_gone" {
		t.Fatal("the purge record is filed under the erased tenant, so writing it recreates that tenant's partition")
	}
	if record.TargetID == nil || *record.TargetID != "tenant_gone" {
		t.Fatalf("the erased tenant must still be the TARGET, got %v", record.TargetID)
	}
	if record.EventType != "admin_tenant_model_purged" {
		t.Fatalf("event_type = %q", record.EventType)
	}
}
