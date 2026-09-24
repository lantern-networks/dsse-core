package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

func TestAgentRolloutWritePinnedTenantContext(t *testing.T) {
	for _, query := range []string{"", "?expected_tenant_id=tenant_lab_001", "?expected_tenant_id=other", "?expected_tenant_id="} {
		for _, intent := range []string{"rollout", "follow", "schedule"} {
			t.Run(query+"/"+intent, func(t *testing.T) {
				h, s, out, path := rolloutAuditFixture(t)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				old, foreign := s.Get("tenant_lab_001"), s.Get("other")
				body := map[string]any{"intent": intent, "desired_version": "3.0.0"}
				if intent == "schedule" {
					body["window"] = map[string]any{"local_start": "02:00", "local_end": "06:00"}
				}
				r := steerMutationRequest(h, "PUT", "/admin/agent-rollout"+query, body)
				rejected := query == "?expected_tenant_id=other" || query == "?expected_tenant_id="
				rows := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
				if rejected {
					after, err := os.ReadFile(path)
					if r.Code != 409 || err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(s.Get("tenant_lab_001"), old) || len(out.insertedAudits) != 0 || len(rows) != 1 {
						t.Fatal("context refusal changed state/domain audit", r.Code, r.Body, rows)
					}
					if rows[0]["result"] != "error" {
						t.Fatal("common refusal result", rows)
					}
				} else {
					if r.Code != 200 {
						t.Fatal(r.Code, r.Body)
					}
					var ack struct {
						Tenant string                        `json:"tenant_id"`
						Plan   agentrollout.AgentRolloutPlan `json:"plan"`
					}
					if err := json.Unmarshal(r.Body.Bytes(), &ack); err != nil {
						t.Fatal(err)
					}
					if ack.Tenant != "tenant_lab_001" || !reflect.DeepEqual(ack.Plan, s.Get("tenant_lab_001")) || !ack.Plan.Frozen || ack.Plan.Reason != old.Reason {
						t.Fatal("ACK is not merged committed plan", ack)
					}
					restart := agentrollout.NewAgentRolloutStore()
					if err := restart.LoadFrom(path); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(restart.Get("tenant_lab_001"), ack.Plan) || len(rows) != 3 || len(out.insertedAudits) != 2 {
						t.Fatal("restart/audit mismatch")
					}
				}
				if !reflect.DeepEqual(s.Get("other"), foreign) {
					t.Fatal("foreign plan changed")
				}
				for _, a := range rows {
					if a["actor_user_id"] != "rollout-admin" || a["tenant_id"] != "tenant_lab_001" {
						t.Fatal("audit attribution", a)
					}
				}
			})
		}
	}
}

func TestRolloutContextPinIncludesLegacyEmptyScope(t *testing.T) {
	for _, tenant := range []string{"", "own"} {
		for _, query := range []string{"", "?expected_tenant_id=", "?expected_tenant_id=own", "?expected_tenant_id=other"} {
			r := httptest.NewRequest("PUT", "/admin/agent-rollout"+query, nil)
			r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: tenant}))
			w := httptest.NewRecorder()
			want := !r.URL.Query().Has("expected_tenant_id") || r.URL.Query().Get("expected_tenant_id") == tenant
			if got := rolloutTenantContextMatches(w, r); got != want || (!got && w.Code != 409) {
				t.Fatalf("tenant=%q query=%q got=%v status=%d", tenant, query, got, w.Code)
			}
		}
	}
}
