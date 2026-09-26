package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

type policyOutcomePublisher struct {
	fail  bool
	calls atomic.Int64
}

func (p *policyOutcomePublisher) PublishAdminPolicySnapshot(context.Context, string, policy.RuntimeStore, model.PolicyBundle, time.Time) error {
	p.calls.Add(1)
	if p.fail {
		return fmt.Errorf("private-publication-sentinel")
	}
	return nil
}

func TestAdminPolicyPublicationOutcomes(t *testing.T) {
	for _, operation := range []string{"upsert", "delete", "status"} {
		for _, publication := range []string{"unconfirmed", "published", "not_requested"} {
			t.Run(operation+"/"+publication, func(t *testing.T) {
				tenant := "tenant_lab_001"
				now := time.Now()
				store := policy.NewStore(nil)
				path := filepath.Join(t.TempDir(), "policies.json")
				if err := store.SetRuntimeStatePath(path); err != nil {
					t.Fatal(err)
				}
				item := model.Policy{ID: "policy-target", Name: "private-policy-name", Status: "active", Conditions: map[string]any{"actor_nhi_id": "agent"}, AllowedToolIDs: []string{"read_repo"}, Action: model.PolicyAction{Decision: "allow"}, Metadata: map[string]any{"secret": "private-policy-secret"}}
				if operation != "upsert" {
					if _, err := store.Upsert(context.Background(), item, tenant, now); err != nil {
						t.Fatal(err)
					}
				}
				auth := newAdminAuthStore()
				auth.UpsertPrincipal(adminPrincipal{ID: "policy-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
				auth.UpsertAPIToken(adminAPIToken{ID: "fixture", TenantID: tenant, TokenHash: adminTokenHash("private-policy-token"), CreatedByAdminPrincipalID: "policy-admin", Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
				writer, err := logs.NewWriter(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				pub := &policyOutcomePublisher{fail: publication == "unconfirmed"}
				var publisher networkExtensionSnapshotPublisher = pub
				if publication == "not_requested" {
					publisher = nil
				}
				h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, AdminAuth: auth, Writer: writer, NetworkExtensionPublisher: publisher})
				b, _ := json.Marshal(item)
				method, url := "POST", "/admin/policies"
				if operation == "delete" {
					method, url = "DELETE", "/admin/policies/policy-target"
				}
				if operation == "status" {
					method, url = "POST", "/admin/policies/policy-target/status"
					b = []byte(`{"status":"disabled"}`)
				}
				req := httptest.NewRequest(method, url, strings.NewReader(string(b)))
				req.Header.Set("Authorization", "Bearer private-policy-token")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				want := 200
				if publication == "unconfirmed" {
					want = 500
				}
				if rec.Code != want {
					t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "private-publication-sentinel") {
					t.Error("internal publisher error leaked")
				}
				if publication == "unconfirmed" {
					var body map[string]any
					json.Unmarshal(rec.Body.Bytes(), &body)
					if body["status"] != "partial" || body["applied"] != true || body["policy_id"] != item.ID || body["tenant_id"] != tenant || body["ne_snapshot_status"] != "unconfirmed" {
						t.Errorf("missing applied outcome: %s", rec.Body.String())
					}
				}
				restart := policy.NewStore(nil)
				if err := restart.SetRuntimeStatePath(path); err != nil {
					t.Fatal(err)
				}
				for _, s := range []*policy.Store{store, restart} {
					got, found, err := s.Get(context.Background(), tenant, item.ID)
					if err != nil || found != (operation != "delete") {
						t.Fatalf("applied state %v %v %+v", found, err, got)
					}
					if operation == "status" && got.Status != "disabled" {
						t.Fatal("status not durable")
					}
					if found && got.AllowedToolIDs[0] != "read_repo" {
						t.Fatal("saved boundary differs")
					}
				}
				rows := readConnectorManagementAudits(t, writer)
				if len(rows) != 2 {
					t.Fatalf("audit count %d, expected domain and common", len(rows))
				}
				event := "admin_policy_upserted"
				if operation == "delete" {
					event = "admin_policy_deleted"
				}
				if operation == "status" {
					event = "admin_policy_status_changed"
				}
				domain := rows[0]
				result, common := "success", "success"
				if publication == "unconfirmed" {
					result, common = "partial", "error"
				}
				if domain.EventType != event || stringPtrValue(domain.Action) != operation || stringPtrValue(domain.Result) != result || stringPtrValue(domain.ActorUserID) != "policy-admin" || domain.TenantID != tenant || stringPtrValue(domain.TargetID) != item.ID || domain.Metadata["applied"] != true || domain.Metadata["ne_snapshot_status"] != publication {
					t.Fatalf("domain %+v", domain)
				}
				if rows[1].EventType != "admin_config_change" || stringPtrValue(rows[1].Result) != common {
					t.Fatal("missing common outcome")
				}
				domain.ActorUserID = nil
				assertAuditLogNonSecretInvariant(t, domain, []string{"private-policy-name", "private-policy-secret", "private-policy-token", "private-publication-sentinel"})
				if publication == "unconfirmed" {
					pub.fail = false
					retry := httptest.NewRequest(method, url, strings.NewReader(string(b)))
					retry.Header.Set("Authorization", "Bearer private-policy-token")
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, retry)
					want := 200
					if operation == "delete" {
						want = 404
					}
					if rr.Code != want {
						t.Fatalf("retry outcome: %d %s", rr.Code, rr.Body)
					}
					// A deletion already committed is not re-created by retrying it.
					if operation != "delete" && pub.calls.Load() != 2 {
						t.Fatal("snapshot retry not attempted")
					}
				}

			})
		}
	}
}

func TestAdminPolicyRejectedSaveDoesNotPublishOrClaimApplied(t *testing.T) {
	store := policy.NewStore(nil)
	p := &ruleAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}}
	if err := store.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	writer, _ := logs.NewWriter(t.TempDir())
	pub := &policyOutcomePublisher{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, Writer: writer, AdminAuth: newAdminAuthStore(), NetworkExtensionPublisher: pub})
	p.fail.Store(true)
	gen := store.ConfigGeneration()
	req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader(`{"id":"rejected","name":"Rejected","conditions":{"actor_nhi_id":"agent"},"action":{"decision":"deny"}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), `"applied":true`) || pub.calls.Load() != 0 || store.ConfigGeneration() != gen {
		t.Fatalf("rejected save: %d %s calls=%d", rec.Code, rec.Body.String(), pub.calls.Load())
	}
	if _, found, _ := store.Get(context.Background(), "tenant_lab_001", "rejected"); found {
		t.Fatal("rejected policy applied")
	}
	if _, err := os.Stat(filepath.Join(writer.Dir(), "audit.log.jsonl")); err == nil {
		for _, r := range readConnectorManagementAudits(t, writer) {
			if r.EventType == "admin_policy_upserted" {
				t.Fatal("domain success for rejected save")
			}
		}
	}
}

func TestAdminPolicyRealPublisherPartialFilesAreUnconfirmed(t *testing.T) {
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePath(filepath.Join(t.TempDir(), "state.json")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pub, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{OutputDir: dir, EdgeURL: "https://edge.example.invalid:443"})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, Writer: writer, AdminAuth: newAdminAuthStore(), NetworkExtensionPublisher: pub})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/policies", strings.NewReader(`{"id":"no-ne-rule","name":"Boundary","conditions":{"actor_nhi_id":"agent"},"action":{"decision":"allow"}}`)))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 500 || body["applied"] != true || body["ne_snapshot_status"] != "unconfirmed" {
		t.Fatalf("outcome: %d %s", rec.Code, rec.Body.String())
	}
	// The real publisher writes the agent config even when there are no eligible steering rules.
	if _, err := os.Stat(filepath.Join(dir, networkExtensionSnapshotAgentConfigRef)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, networkExtensionSnapshotRulesRef)); !os.IsNotExist(err) {
		t.Fatalf("unexpected rules file: %v", err)
	}
	rows := readConnectorManagementAudits(t, writer)
	if rows[0].EventType != "admin_policy_upserted" || stringPtrValue(rows[0].Result) != "partial" {
		t.Fatalf("partial audit: %+v", rows)
	}
}

func TestAdminPolicyMutationAuditOperatorAttribution(t *testing.T) {
	for _, operation := range []string{"upsert", "delete", "status"} {
		for _, status := range []string{"published", "not_requested", "unconfirmed"} {
			req := httptest.NewRequest("POST", "/admin/policies", strings.NewReader("private-body-sentinel"))
			req.Header.Set("Authorization", "private-auth-sentinel")
			req.Header.Set("Cookie", "private-cookie-sentinel")
			req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "operator", TenantID: "operator-tenant"})
			audit := adminPolicyMutationAuditLog(req, model.Policy{ID: "target", TenantID: "customer", Conditions: map[string]any{"actor_nhi_id": "private-actor-sentinel"}}, testEvaluator(), time.Now(), operation, status)
			if stringPtrValue(audit.ActorUserID) != "operator" || audit.Metadata["operator_principal_id"] != "operator" || audit.Metadata["operator_tenant_id"] != "operator-tenant" || audit.TenantID != "customer" {
				t.Fatalf("operator attribution: %+v", audit)
			}
			audit.ActorUserID = nil
			assertAuditLogNonSecretInvariant(t, audit, []string{"private-body-sentinel", "private-auth-sentinel", "private-cookie-sentinel", "private-actor-sentinel"})
		}
	}
}
