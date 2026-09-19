package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func rolloutAuditFixture(t *testing.T) (http.Handler, *agentrollout.AgentRolloutStore, *recordingAdminAuditOutboxDeadReader, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "state", "plans.json")
	s := agentrollout.NewAgentRolloutStore()
	if err := s.LoadFrom(path); err != nil {
		t.Fatal(err)
	}
	n := 11
	p := agentrollout.AgentRolloutPlan{DesiredVersion: "2.0.0", ReleaseChannel: "stable", Frozen: true, Reason: "incident hold", Waves: &agentrollout.WaveSchedule{Waves: []agentrollout.RolloutWave{{Group: "Pilot", Priority: 9}}, DefaultDelayDays: &n}, Window: &agentupdate.PlanWindow{LocalStart: "01:00", LocalEnd: "05:00"}}
	for _, tenant := range []string{"tenant_lab_001", "other"} {
		if err := s.Set(tenant, p); err != nil {
			t.Fatal(err)
		}
	}
	w, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "rollout-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "rollout-token", TokenHash: adminTokenHash("steering-review-token"), TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "rollout-admin", Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	out := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, AgentRolloutPlans: s, AdminAuditOutbox: out})
	return h, s, out, path
}
func TestRolloutEditsRetainHaltAndAuditActor(t *testing.T) {
	for _, intent := range []string{"rollout", "rollback", "follow", "schedule"} {
		t.Run(intent, func(t *testing.T) {
			h, s, out, path := rolloutAuditFixture(t)
			prior := s.Get("tenant_lab_001")
			foreign := s.Get("other")
			body := map[string]any{"intent": intent, "desired_version": "3.0.0"}
			if intent == "schedule" {
				body["window"] = map[string]any{"local_start": "02:00", "local_end": "06:00"}
			}
			r := steerMutationRequest(h, "PUT", "/admin/agent-rollout", body)
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body)
			}
			got := s.Get("tenant_lab_001")
			if !got.Frozen || got.Reason != prior.Reason || !reflect.DeepEqual(got.Waves, prior.Waves) {
				t.Fatal("independent controls changed", got)
			}
			if !reflect.DeepEqual(s.Get("other"), foreign) {
				t.Fatal("other tenant changed")
			}
			rows := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
			if len(rows) != 3 || len(out.insertedAudits) != 2 {
				t.Fatal("audit records", rows)
			}
			for _, a := range rows {
				if a["actor_user_id"] != "rollout-admin" || a["tenant_id"] != "tenant_lab_001" {
					t.Fatal("audit identity", a)
				}
			}
			if _, misleading := out.insertedAudits[0].Metadata["frozen_requested"]; misleading {
				t.Fatal("version/schedule attempt must not claim the caller requested a hold change")
			}
			for _, a := range out.insertedAudits {
				if a.ActorUserID == nil || *a.ActorUserID != "rollout-admin" || a.TargetID == nil || *a.TargetID != "tenant_lab_001" {
					t.Fatal("mirror identity", a)
				}
			}
			restored := agentrollout.NewAgentRolloutStore()
			if err := restored.LoadFrom(path); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, restored.Get("tenant_lab_001")) {
				t.Fatal("restart state")
			}
		})
	}
}
func TestRolloutFailedSaveKeepsStateAndAuditsActor(t *testing.T) {
	h, s, out, path := rolloutAuditFixture(t)
	prior := s.Get("tenant_lab_001")
	dir := filepath.Dir(path)
	if err := os.Rename(dir, dir+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	r := steerMutationRequest(h, "PUT", "/admin/agent-rollout", map[string]any{"intent": "rollout", "desired_version": "3.0.0"})
	if r.Code != 500 {
		t.Fatal(r.Code, r.Body)
	}
	if !reflect.DeepEqual(s.Get("tenant_lab_001"), prior) {
		t.Fatal("failed save changed live state")
	}
	var disk map[string]agentrollout.AgentRolloutPlan
	b, err := os.ReadFile(filepath.Join(dir+".saved", "plans.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &disk); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(disk["tenant_lab_001"], prior) {
		t.Fatal("failed save changed disk")
	}
	rows := inventoryMutationAudits(t, filepath.Dir(dir))
	if len(rows) != 3 || len(out.insertedAudits) != 2 {
		t.Fatal("failed audits", rows)
	}
	for _, a := range rows {
		if a["actor_user_id"] != "rollout-admin" {
			t.Fatal("missing actor", a)
		}
	}
	if *out.insertedAudits[0].Result != "attempted" || *out.insertedAudits[1].Result != "failed" {
		t.Fatal("wrong outcome", out.insertedAudits)
	}
}
