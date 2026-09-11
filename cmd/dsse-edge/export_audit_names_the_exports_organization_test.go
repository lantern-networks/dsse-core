package main

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
)

// ★★★ AN EXPORT OF ONE ORGANIZATION'S DATA WAS RECORDED IN ANOTHER'S TRAIL (2026-08-21, read on the lab's own
// audit screen). adminExportJobAuditLog filed every export under evaluator.PolicyBundle.TenantID — the
// organization the NODE belongs to — so an export of tenant_acme's audit stream, requested by Acme's own
// administrator, landed in tenant_reference_lab's stream carrying the object reference, the row count and the
// payload checksum. Two harms in one row: the organization whose data left has no record of it, and an
// unrelated organization reads about it.
func TestAnExportIsRecordedInItsOwnOrganizationsTrail(t *testing.T) {
	node := decision.Evaluator{}
	node.PolicyBundle.TenantID = "tenant_reference_lab"
	ref := "evidence://tenant/tenant_acme/exports/2026/08/20/export_abc.ndjson.gz"

	row := adminExportJobAuditLog("admin_export_completed", adminExportJob{
		ID:        "export_abc",
		TenantID:  "tenant_acme",
		Stream:    "audit",
		Status:    "completed",
		RowCount:  87,
		ObjectRef: &ref,
	}, node, "192.0.2.9")

	if row.TenantID != "tenant_acme" {
		t.Fatalf("★ the export was filed under %q, not the organization whose data it is (tenant_acme). "+
			"On a deployment where the node's organization is also a customer, that is one customer reading "+
			"another's export — object reference, row count and checksum included.", row.TenantID)
	}

	// ★ AND AN UNATTRIBUTED JOB SAYS SO rather than quietly becoming the node's. A silent fallback is how the
	// original defect read as normal for as long as it did.
	orphan := adminExportJobAuditLog("admin_export_completed", adminExportJob{ID: "export_xyz"}, node, "192.0.2.9")
	if orphan.TenantID != "tenant_reference_lab" {
		t.Fatalf("a job naming no organization must still be recorded somewhere; got %q", orphan.TenantID)
	}
	note, _ := orphan.Metadata["tenant_attribution"].(string)
	if !strings.Contains(note, "named no organization") {
		t.Fatalf("an export filed under the node by fallback must say so; metadata was %v", orphan.Metadata)
	}
}
