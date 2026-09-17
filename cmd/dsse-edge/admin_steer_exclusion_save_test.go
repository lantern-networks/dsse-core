package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/steerexclusion"
)

func steerMutationFixture(t *testing.T) (http.Handler, *steerexclusion.Store, *logs.Writer, string) {
	h, s, w, path, _, _ := steerMutationFullFixture(t)
	return h, s, w, path
}
func steerMutationFullFixture(t *testing.T) (http.Handler, *steerexclusion.Store, *logs.Writer, string, *recordingAdminAuditOutboxDeadReader, *configversion.MemoryStore) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "state", "policies.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	s, err := steerexclusion.NewStoreWithPersistence(steerexclusion.NewFilePersistence(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []steerexclusion.Policy{{ID: "owned", TenantID: "tenant_lab_001", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example.prior"}}, {ID: "foreign", TenantID: "tenant_other", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example.foreign"}}} {
		if _, err := s.Upsert(p, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	w, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "steering-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "steering-token", TokenHash: adminTokenHash("steering-review-token"), TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "steering-admin", Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	versions := configversion.NewMemoryStore()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, SteerExclusions: s, AdminAuditOutbox: outbox, ConfigVersions: versions})
	return h, s, w, path, outbox, versions
}
func steerMutationRequest(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer steering-review-token")
	r.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, r)
	return res
}
func TestAdminSteerExclusionForeignID(t *testing.T) {
	h, s, _, path := steerMutationFixture(t)
	before, _ := os.ReadFile(path)
	r := steerMutationRequest(h, "POST", "/admin/steer-exclusions", map[string]any{"id": "foreign", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.stolen"}})
	if r.Code != 403 {
		t.Fatalf("foreign-ID update returned %d, body=%s, foreign=%+v own=%+v", r.Code, r.Body.String(), s.List("tenant_other"), s.List("tenant_lab_001"))
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("foreign file changed")
	}
	if p, ok := s.Get("foreign", "tenant_other"); !ok || p.ExcludedAppSigningIDs[0] != "com.example.foreign" {
		t.Fatal("foreign policy changed")
	}
}
func TestAdminSteerExclusionSaveFailure(t *testing.T) {
	for _, action := range []string{"create", "update", "delete"} {
		t.Run(action, func(t *testing.T) {
			h, s, _, path := steerMutationFixture(t)
			before, _ := os.ReadFile(path)
			dir := filepath.Dir(path)
			if err := os.Rename(dir, dir+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, []byte("blocked parent"), 0600); err != nil {
				t.Fatal(err)
			}
			id := "owned"
			if action == "create" {
				id = "new-rule"
			}
			method, url := "POST", "/admin/steer-exclusions"
			var body any = map[string]any{"id": id, "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.changed"}}
			if action == "delete" {
				method = "DELETE"
				url += "/owned"
				body = nil
			}
			r := steerMutationRequest(h, method, url, body)
			if r.Code != 500 {
				t.Fatalf("%s failed save returned %d: %s; live=%+v", action, r.Code, r.Body.String(), s.List("tenant_lab_001"))
			}
			if p, ok := s.Get("owned", "tenant_lab_001"); !ok || p.ExcludedAppSigningIDs[0] != "com.example.prior" {
				t.Fatal("failed write changed live policy")
			}
			if _, ok := s.Get("new-rule", "tenant_lab_001"); ok {
				t.Fatal("failed create published")
			}
			after, _ := os.ReadFile(filepath.Join(dir+".saved", "policies.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("old file changed")
			}
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(dir+".saved", dir); err != nil {
				t.Fatal(err)
			}
			r = steerMutationRequest(h, method, url, body)
			if r.Code != 200 {
				t.Fatal("retry", r.Code, r.Body.String())
			}
			restored, err := steerexclusion.NewStoreWithPersistence(steerexclusion.NewFilePersistence(path))
			if err != nil {
				t.Fatal(err)
			}
			p, ok := restored.Get(id, "tenant_lab_001")
			if action == "delete" {
				if ok {
					t.Fatal("deleted policy restored")
				}
			} else if !ok || p.ExcludedAppSigningIDs[0] != "com.example.changed" {
				t.Fatal("saved policy missing")
			}
		})
	}
}

func TestAdminSteerExclusionMutationAuditAndRollback(t *testing.T) {
	for _, action := range []string{"upsert", "delete", "rollback"} {
		t.Run(action, func(t *testing.T) {
			h, s, _, path, outbox, versions := steerMutationFullFixture(t)
			tenant := "tenant_lab_001"
			prior, _ := s.Get("owned", tenant)
			if _, err := versions.Record(context.Background(), tenant, configversion.ResourceSteerExclusion, "owned", configversion.ActionUpsert, "seed", "seed", prior); err != nil {
				t.Fatal(err)
			}
			// Move the current policy away from the version used by rollback.
			current := prior
			current.ExcludedAppSigningIDs = []string{"com.example.current"}
			var err error
			current, err = s.Upsert(current, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			method, url := "POST", "/admin/steer-exclusions"
			var body any = map[string]any{"id": "owned", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.new"}}
			if action == "delete" {
				method, url, body = "DELETE", "/admin/steer-exclusions/owned", nil
			}
			if action == "rollback" {
				url, body = "/admin/steer-exclusions/owned/rollback", map[string]int{"version_no": 1}
			}
			dir := filepath.Dir(path)
			if err := os.Rename(dir, dir+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, []byte("blocked"), 0600); err != nil {
				t.Fatal(err)
			}
			failed := steerMutationRequest(h, method, url, body)
			if failed.Code != 500 || !strings.Contains(failed.Body.String(), "Saving could not be confirmed") || strings.Contains(failed.Body.String(), dir) {
				t.Fatal("unsafe or false failure response", failed.Code, failed.Body.String())
			}
			held, _ := s.Get("owned", tenant)
			if !reflect.DeepEqual(held, current) {
				t.Fatal("failed write changed state")
			}
			history, err := versions.List(context.Background(), tenant, configversion.ResourceSteerExclusion, "owned")
			if err != nil || len(history) != 1 {
				t.Fatal("failed write created history", history, err)
			}
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(dir+".saved", dir); err != nil {
				t.Fatal(err)
			}
			retry := steerMutationRequest(h, method, url, body)
			if retry.Code != 200 {
				t.Fatal("retry", retry.Code, retry.Body.String())
			}
			history, err = versions.List(context.Background(), tenant, configversion.ResourceSteerExclusion, "owned")
			if err != nil || len(history) != 2 || history[0].Action != action {
				t.Fatal("history", history, err)
			}
			got, exists := s.Get("owned", tenant)
			if action == "rollback" && (!exists || got.ExcludedAppSigningIDs[0] != "com.example.prior") {
				t.Fatal("rollback not restored")
			}
			rows := inventoryMutationAudits(t, filepath.Dir(dir))
			if len(rows) != 4 {
				t.Fatal("audit count", len(rows))
			}
			domains := []map[string]any{}
			for _, r := range rows {
				if r["actor_user_id"] != "steering-admin" || r["tenant_id"] != tenant {
					t.Fatal("audit actor or owner", r)
				}
				if r["event_type"] == "steer_exclusion_updated" {
					domains = append(domains, r)
				}
			}
			if len(domains) != 2 || domains[0]["result"] != "failed" || domains[1]["result"] != "success" {
				t.Fatal("domain audit", domains)
			}
			for i, r := range domains {
				if r["target_id"] != "owned" || r["action"] != "steer_exclusion_"+action {
					t.Fatal("audit target", r)
				}
				meta := r["metadata"].(map[string]any)
				if meta["applied_locally"] != (i == 1) {
					t.Fatal("audit local result", r)
				}
				if i == 0 && meta["persistence_error"] != true {
					t.Fatal("audit storage result", r)
				}
			}
			mirrorJSON, _ := json.Marshal(outbox.insertedAudits)
			var mirror []map[string]any
			if err = json.Unmarshal(mirrorJSON, &mirror); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(mirror, domains) {
				t.Fatal("outbox differs from original domain audits")
			}
		})
	}
}

func TestAdminSteerExclusionRejectionsDoNotMutate(t *testing.T) {
	for _, tt := range []struct {
		name, method, path string
		body               any
		status             int
	}{
		{"foreign-id", "POST", "/admin/steer-exclusions", map[string]any{"id": "foreign", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.attack"}}, 403},
		{"foreign-body", "POST", "/admin/steer-exclusions", map[string]any{"id": "new", "tenant_id": "tenant_other", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.attack"}}, 403},
		{"foreign-delete", "DELETE", "/admin/steer-exclusions/foreign", nil, 404},
		{"missing-delete", "DELETE", "/admin/steer-exclusions/missing", nil, 404},
		{"invalid-scope", "POST", "/admin/steer-exclusions", map[string]any{"id": "owned", "scope_type": "unknown", "excluded_app_signing_ids": []string{"com.example.attack"}}, 400},
		{"foreign-id-rollback", "POST", "/admin/steer-exclusions/foreign/rollback", map[string]int{"version_no": 1}, 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, s, _, path, outbox, versions := steerMutationFullFixture(t)
			// A legacy version can name an ID now held by another tenant. Rollback must
			// pass through the same live and durable ownership checks as an upsert.
			if _, err := versions.Record(context.Background(), "tenant_lab_001", configversion.ResourceSteerExclusion, "foreign", configversion.ActionUpsert, "seed", "", steerexclusion.Policy{ID: "foreign", TenantID: "tenant_lab_001", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example.old"}}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			own, foreign := s.List("tenant_lab_001"), s.List("tenant_other")
			r := steerMutationRequest(h, tt.method, tt.path, tt.body)
			if r.Code != tt.status {
				t.Fatal("status", r.Code, r.Body.String())
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !reflect.DeepEqual(own, s.List("tenant_lab_001")) || !reflect.DeepEqual(foreign, s.List("tenant_other")) {
				t.Fatal("rejected write changed policy state")
			}
			if len(outbox.insertedAudits) != 0 {
				t.Fatal("rejection created mutation domain audit")
			}
			rows := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
			if len(rows) != 1 || rows[0]["event_type"] == "steer_exclusion_updated" || rows[0]["result"] != "error" || rows[0]["actor_user_id"] != "steering-admin" {
				t.Fatal("missing common rejection audit", rows)
			}
		})
	}
}

func TestAdminSteerExclusionOperatorBodyAuditOwnership(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "failed"}[fail], func(t *testing.T) {
			_, s, w, path, outbox, versions := steerMutationFullFixture(t)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "steering-operator", TenantID: "operator", Roles: []string{"owner"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "operator-token", TokenHash: adminTokenHash("steering-review-token"), TenantID: "operator", CreatedByAdminPrincipalID: "steering-operator", Roles: []string{"owner"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: "operator", Writer: w, AdminAuth: auth, SteerExclusions: s, AdminAuditOutbox: outbox, ConfigVersions: versions})
			if fail {
				dir := filepath.Dir(path)
				if err := os.Rename(dir, dir+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dir, []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := steerMutationRequest(h, "POST", "/admin/steer-exclusions", map[string]any{"id": "operator-authored", "tenant_id": "tenant_other", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.owned"}})
			want := 200
			if fail {
				want = 500
			}
			if r.Code != want {
				t.Fatal("operator body write", r.Code, r.Body.String())
			}
			_, exists := s.Get("operator-authored", "tenant_other")
			if exists == fail {
				t.Fatal("target policy result", exists)
			}
			target, err := versions.List(context.Background(), "tenant_other", configversion.ResourceSteerExclusion, "operator-authored")
			if err != nil {
				t.Fatal(err)
			}
			expected := 1
			if fail {
				expected = 0
			}
			if len(target) != expected {
				t.Fatal("target history", target)
			}
			for _, tenant := range []string{"operator", "tenant_lab_001"} {
				wrong, err := versions.List(context.Background(), tenant, configversion.ResourceSteerExclusion, "operator-authored")
				if err != nil || len(wrong) != 0 {
					t.Fatal("history attributed to wrong tenant", wrong, err)
				}
			}
			rows := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
			var domain map[string]any
			for _, row := range rows {
				if row["event_type"] == "steer_exclusion_updated" {
					domain = row
				}
			}
			if domain == nil || domain["tenant_id"] != "tenant_other" || domain["actor_user_id"] != "steering-operator" || domain["target_id"] != "operator-authored" {
				t.Fatal("operator target audit", domain)
			}
			result := "success"
			if fail {
				result = "failed"
			}
			if domain["result"] != result {
				t.Fatal("operator result", domain)
			}
			if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].TenantID != "tenant_other" {
				t.Fatal("operator mirror tenant", outbox.insertedAudits)
			}
		})
	}
}
