package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

func TestAgentRolloutReadPinnedTenantContext(t *testing.T) {
	h, store, outbox, path := rolloutAuditFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan := store.Get("tenant_lab_001")
	foreign := store.Get("other")
	for _, query := range []string{"", "?expected_tenant_id=tenant_lab_001", "?tenant_id=other", "?expected_tenant_id=other"} {
		r := steerMutationRequest(h, "GET", "/admin/agent-rollout"+query, nil)
		if strings.Contains(query, "expected_tenant_id=other") {
			if r.Code != 409 || strings.Contains(r.Body.String(), "incident hold") || strings.Contains(r.Body.String(), "desired_version") {
				t.Fatal("foreign context returned plan", r.Code, r.Body)
			}
			continue
		}
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
		var body struct {
			Schema string                        `json:"schema_version"`
			Tenant string                        `json:"tenant_id"`
			Plan   agentrollout.AgentRolloutPlan `json:"plan"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Schema != "admin_agent_rollout.v1" || body.Tenant != "tenant_lab_001" || !reflect.DeepEqual(body.Plan, plan) {
			t.Fatal("read contract changed", body)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(store.Get("other"), foreign) || len(outbox.insertedAudits) != 0 {
		t.Fatal("read changed rollout state or domain audit")
	}
}
