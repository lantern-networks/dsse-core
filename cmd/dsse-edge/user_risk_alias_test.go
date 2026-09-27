package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestDecisionRiskFollowsDirectoryAliasUpdate(t *testing.T) {
	ctx := context.Background()
	directory := humanidentity.NewHumanIdentityDirectoryStore()
	risk := revocation.NewHighRiskOverlay()
	now := time.Now()
	person, err := directory.Upsert(ctx, model.HumanIdentity{ID: "person", Subject: "old-subject", Source: "idp"}, "tenant_lab_001", now)
	if err != nil {
		t.Fatal(err)
	}
	mark := directoryRiskMark(person)
	mark.Severity = "high"
	if _, err := risk.SetUserRisk(mark); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{
		{ID: "deny-risk", TenantID: "tenant_lab_001", Priority: 10, Status: "active", Conditions: map[string]any{"risk_state_severity": []any{"high", "critical"}}, Action: model.PolicyAction{Decision: "deny"}},
		{ID: "allow-rest", TenantID: "tenant_lab_001", Priority: 100, Status: "active", Conditions: map[string]any{"application_id": "app_dummy_postgres"}, Action: model.PolicyAction{Decision: "allow"}},
	}), HumanIdentities: directory, HighRiskOverlay: risk, Writer: writer})
	email := "new@example.invalid"
	person.Subject = "new-subject"
	person.Email = &email
	if _, err := directory.Upsert(ctx, person, "tenant_lab_001", now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"person", "old-subject", "new-subject", email, "clean"} {
		r := httptest.NewRequest("POST", "/decisions/evaluate", strings.NewReader(`{"tenant_id":"tenant_lab_001","user_id":"`+id+`","application_id":"app_dummy_postgres","service_family":"database","destination_port":5432,"protocol":"tcp"}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var dec model.AccessDecision
		if err := json.Unmarshal(w.Body.Bytes(), &dec); err != nil || w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if id == "clean" {
			if dec.Decision != "allow" || dec.Metadata["risk_state_severity"] != nil {
				t.Fatalf("clean user was not allowed: %s", w.Body.String())
			}
			continue
		}
		if dec.Metadata["risk_state_severity"] != "high" || dec.Decision != "deny" || dec.PolicyID != "deny-risk" {
			t.Fatalf("user %q lost high risk: %s", id, w.Body.String())
		}
	}
}
