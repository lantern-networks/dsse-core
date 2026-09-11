package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ A CUSTOMER'S OWN RECORD NAMED ANOTHER ORGANIZATION (2026-08-20, measured with a real customer session
// sweeping 121 routes: /admin/state handed tenant_northwind's administrator the string "tenant_reference_lab").
//
// The refusal record carried the organization the NODE belongs to. The standing policy — audit records are not
// edited — stands, and nothing already written is touched: what changed is that this is not written, which is a
// different act. The record still says which node answered, through its region and cluster, and that is what an
// investigation uses. The field had no reader anywhere in the tree.
func TestARefusalRecordNamesNoOrganizationButTheReadersOwn(t *testing.T) {
	evaluator := decision.Evaluator{
		PolicyBundle:  model.PolicyBundle{TenantID: "tenant_the_node_belongs_to"},
		EdgeRegionID:  "region-a",
		EdgeClusterID: "cluster-1",
	}
	entry := adminRBACDeniedAuditLog(adminIdentity{
		PrincipalID: "adm_customer", TenantID: "tenant_the_reader", Roles: []string{"admin"},
		AuthMethod: "admin_session",
	}, "admin.something.write", evaluator, "1.2.3.4", "curl")

	blob, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "tenant_the_node_belongs_to") {
		t.Fatalf("a record this customer reads on their own screen names the node's organization: %s", blob)
	}
	if !strings.Contains(string(blob), "tenant_the_reader") {
		t.Fatal("the record no longer names the organization it is about")
	}
	// The node is still identified — an investigation needs to know which one answered.
	if !strings.Contains(string(blob), "region-a") || !strings.Contains(string(blob), "cluster-1") {
		t.Fatalf("the record no longer says which node refused: %s", blob)
	}
}
