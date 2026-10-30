package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRiskAndAdmissionAuditsRetainCaseDistinctOperatorProvenance(t *testing.T) {
	req := requestWithAdminIdentity(httptest.NewRequest(http.MethodPost, "/admin/risk", nil),
		adminIdentity{PrincipalID: "operator", TenantID: "Acme"})
	now := time.Now().UTC()
	evaluator := testEvaluator()
	for name, audit := range map[string]model.AuditLog{
		"device_risk":         deviceRiskAuditLog(req, "acme", adminRiskSignalResponse{EntityID: "device"}, evaluator, now),
		"user_risk":           userRiskAuditLog(req, "acme", adminRiskSignalResponse{EntityID: "user"}, evaluator, now),
		"transport_admission": transportAdmissionAuditLog(req, "acme", "revoke", "device", "test", evaluator, now),
	} {
		if audit.TenantID != "acme" || audit.Metadata["operator_principal_id"] != "operator" || audit.Metadata["operator_tenant_id"] != "Acme" {
			t.Errorf("%s lost case-distinct operator provenance", name)
		}
	}
}
