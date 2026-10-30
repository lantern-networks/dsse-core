package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/usagemeter"
)

func TestAdminUsageSummaryUsesMeasuredZeroWhenRegisteredNHIIsSuspended(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tenantID := "tenant_usage_zero"
	actorNHIID := "nhi_suspended"
	usageMeters := usagemeter.NewUsageMeterStore(usagemeter.UsageMeterRecordFromAccessDecision(model.AccessDecision{
		TenantID:   tenantID,
		ActorType:  "delegated_agent",
		ActorNHIID: &actorNHIID,
	}, now))
	registry := nhi.NewStore()
	if _, err := registry.Upsert(context.Background(), model.NonHumanIdentity{
		ID: actorNHIID, Name: "Suspended Agent", NHIType: "ai_agent", OwnerUserID: "owner", Status: "suspended",
	}, tenantID, now); err != nil {
		t.Fatal(err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID: "admin_usage_zero", TenantID: tenantID, Subject: "admin_usage_zero", Email: "usage-zero@example.invalid",
		Roles: []string{"owner"}, IDPID: "test_idp", Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID: "admin_session_usage_zero", TenantID: tenantID, AdminPrincipalID: "admin_usage_zero", Subject: "admin_usage_zero",
		Roles: []string{"owner"}, AuthTime: now.Add(-time.Minute).Format(time.RFC3339), MFAState: "fresh",
		CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		LastActiveAt: now.Format(time.RFC3339), Status: "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, UsageMeters: usageMeters, AdminAuth: adminAuth,
		NonHumanIdentities: registry, LabMode: boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_session_usage_zero"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var summary usagemeter.UsageMeterSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if got := summary.Meters["nhi_seat"].Quantity; got != 0 {
		t.Fatalf("suspended registry's measured NHI seats = %v, want 0; observed usage must not override it", got)
	}
}
