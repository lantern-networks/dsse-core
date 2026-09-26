package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestPostgresPolicyAdminPeerLifecycle(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "policy_admin_runtime")
	handlers := make([]http.Handler, 2)
	for i := range handlers {
		s := policy.NewStore(nil)
		if err := s.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
		handlers[i] = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, AdminAuth: newAdminAuthStore()})
	}
	call := func(i int, method, path, body string, want int) []byte {
		t.Helper()
		r := doAdmin(t, handlers[i], method, path, body)
		if r.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body)
		}
		return r.Body.Bytes()
	}
	body := `{"id":"peer-policy","name":"Created","conditions":{"service_family":"ssh"},"action":{"decision":"deny"},"status":"active"}`
	call(0, "POST", "/admin/policies", body, 200)
	call(1, "POST", "/admin/policies", strings.Replace(body, "Created", "Edited", 1), 200)
	for i, status := range []string{"disabled", "active"} {
		call(i%2, "POST", "/admin/policies/peer-policy/status", `{"status":"`+status+`"}`, 200)
		raw := call((i+1)%2, "GET", "/admin/policies/peer-policy", "", 200)
		var item model.Policy
		if err := json.Unmarshal(raw, &item); err != nil || item.Status != status || item.Name != "Edited" {
			t.Fatalf("detail: %s", raw)
		}
		raw = call((i+1)%2, "GET", "/admin/policies", "", 200)
		var list policy.ListResponse
		if err := json.Unmarshal(raw, &list); err != nil || len(list.Policies) != 1 || list.Policies[0].Status != status {
			t.Fatalf("list: %s", raw)
		}
	}
	call(1, "DELETE", "/admin/policies/peer-policy", "", 200)
	call(0, "GET", "/admin/policies/peer-policy", "", 404)
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	call(0, "GET", "/admin/policies", "", 503)
}

func TestAdminPolicyStatusSaveFailureDoesNotPublish(t *testing.T) {
	p := &ruleAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "policies.json")}}
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	pub := &policyOutcomePublisher{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, AdminAuth: newAdminAuthStore(), NetworkExtensionPublisher: pub})
	r := doAdmin(t, h, "POST", "/admin/policies", `{"id":"status-policy","status":"active","conditions":{"service_family":"ssh"},"action":{"decision":"deny"}}`)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	p.fail.Store(true)
	before := pub.calls.Load()
	r = doAdmin(t, h, "POST", "/admin/policies/status-policy/status", `{"status":"disabled"}`)
	if r.Code != 503 || pub.calls.Load() != before || strings.Contains(r.Body.String(), "private-runtime-location") {
		t.Fatalf("failure: %d %s", r.Code, r.Body)
	}
	var item model.Policy
	r = doAdmin(t, h, "GET", "/admin/policies/status-policy", "")
	json.Unmarshal(r.Body.Bytes(), &item)
	if item.Status != "active" {
		t.Fatal("failed toggle changed active policy")
	}
	r = doAdmin(t, h, "DELETE", "/admin/policies/status-policy", "")
	if r.Code != 503 || pub.calls.Load() != before || strings.Contains(r.Body.String(), "private-runtime-location") {
		t.Fatalf("failed deletion: %d %s", r.Code, r.Body)
	}
	p.fail.Store(false)
	r = doAdmin(t, h, "POST", "/admin/policies/status-policy/status", `{"status":"disabled"}`)
	if r.Code != 200 || pub.calls.Load() != before+1 {
		t.Fatalf("retry: %d %s", r.Code, r.Body)
	}
}
