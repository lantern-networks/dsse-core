package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

func TestCandidateAdminSaveFailureAndRetry(t *testing.T) {
	for _, op := range []string{"create", "review", "materialize", "manual-bypass", "publish-app", "refresh"} {
		t.Run(op, func(t *testing.T) {
			ctx, now := context.Background(), time.Now()
			const tenant = "tenant_lab_001"
			disk := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "candidates.json")}
			gate := &rejectingRoutePersister{Persister: disk}
			candidates := policycandidate.NewStore()
			if err := candidates.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			seed, err := candidates.ObserveConnectorDiscovered(ctx, tenant, "wiki.example.test", 443, "web", "connector", "site", "", nil, now)
			if op != "publish-app" {
				seed, err = candidates.ObserveUnmatchedFlow(ctx, tenant, "observed.example.test", "", 443, "", now)
			}
			if err != nil {
				t.Fatal(err)
			}
			if op == "materialize" {
				if _, _, err := candidates.Review(ctx, tenant, seed.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := candidates.List(ctx, tenant, policycandidate.ListOptions{})
			apps := appcatalog.NewStore()
			appDisk := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "apps.json")}
			if err := apps.SetStatePath(appDisk.Path); err != nil {
				t.Fatal(err)
			}
			policies := policy.NewStore(nil)
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			applies := 0
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), Writer: writer, AdminAuditOutbox: outbox, PolicyCandidateStore: candidates, ApplicationCatalogStore: apps, PolicyStore: policies, ApplyMaterializedCertPinBypass: func(string) { applies++ }})
			if op == "refresh" {
				req := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{"id":"conn-disc","tenant_id":"tenant_lab_001","connector_group_id":"site","name":"Fixture connector","edge_region_id":"local","edge_cluster_id":"local-edge-001","private_base_url":"http://connector.invalid","status":"registered","reachable_routes":{"fqdn_domains":["new-discovery.example.test"]}}`))
				req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusCreated {
					t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
				}
			}
			path, body := "/admin/policy-candidates/"+seed.CandidateID+"/review", `{"decision":"suppressed"}`
			switch op {
			case "refresh":
				path = "/admin/connector-discovery/refresh"
				body = ""
			case "create":
				path = "/admin/policy-candidates"
				n := seed
				n.CandidateID = "new-candidate"
				raw, _ := json.Marshal(n)
				body = string(raw)
			case "materialize":
				path = "/admin/policy-candidates/" + seed.CandidateID + "/materialize"
				body = ""
			case "manual-bypass":
				path = "/admin/cert-pin-bypass"
				body = `{"host":"pinned.example.test"}`
			case "publish-app":
				path = "/admin/policy-candidates/" + seed.CandidateID + "/approve-private-app"
				body = `{"publish_protocol":"web"}`
			}
			request := func() *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
				return rec
			}
			priorApplies := applies
			gate.fail = true
			rec := request()
			want := http.StatusServiceUnavailable
			if op == "publish-app" {
				want = http.StatusInternalServerError
			}
			if rec.Code != want {
				t.Fatalf("failed save status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "private database connection detail") {
				t.Fatal("backend detail leaked")
			}
			after, _ := candidates.List(ctx, tenant, policycandidate.ListOptions{})
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected candidate changed live state")
			}
			if applies != priorApplies {
				t.Fatal("failed candidate save applied bypass")
			}
			active, _ := policies.List(ctx, tenant, policy.ListOptions{})
			if active.Count != 0 {
				t.Fatal("failed candidate save adopted policy")
			}
			if op == "publish-app" {
				var response map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response["partial"] != true || response["failed_stage"] != "candidate_review" {
					t.Fatalf("missing partial result: %v", response)
				}
				freshApps := appcatalog.NewStore()
				if err := freshApps.SetStatePath(appDisk.Path); err != nil {
					t.Fatal(err)
				}
				app, found, err := freshApps.Get(ctx, tenant, seed.CandidateID)
				if err != nil || !found || !app.Published {
					t.Fatal("confirmed app publication lost")
				}
				foundPartial := false
				for _, audit := range outbox.insertedAudits {
					if audit.EventType == "admin_policy_candidate_reviewed" && audit.Result != nil && *audit.Result == "partial" && audit.Metadata["application_saved"] == true && audit.Metadata["candidate_saved"] == false {
						foundPartial = true
					}
				}
				if !foundPartial {
					t.Fatal("partial publication not audited")
				}
			}
			gate.fail = false
			rec = request()
			if rec.Code != http.StatusOK {
				t.Fatalf("retry=%d %s", rec.Code, rec.Body.String())
			}
			fresh := policycandidate.NewStore()
			if err := fresh.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			live, _ := candidates.List(ctx, tenant, policycandidate.ListOptions{})
			reloaded, _ := fresh.List(ctx, tenant, policycandidate.ListOptions{})
			if !reflect.DeepEqual(live, reloaded) || reflect.DeepEqual(before, live) {
				t.Fatal("retry not durably applied")
			}
		})
	}
}

func TestConnectorDiscoveryRefreshSkipsInvalidNamespace(t *testing.T) {
	ctx := context.Background()
	candidates := policycandidate.NewStore()
	disk := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "candidates.json")}
	if err := candidates.SetPersister(disk); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), Writer: writer, PolicyCandidateStore: candidates})
	for _, entry := range []struct{ id, namespace, domain string }{{"conn-invalid", "invalid namespace", "invalid.example.test"}, {"conn-valid", "office", "valid.example.test"}} {
		body, _ := json.Marshal(map[string]any{"id": entry.id, "tenant_id": "tenant_lab_001", "connector_group_id": "site", "name": "Fixture connector", "edge_region_id": "local", "edge_cluster_id": "local-edge-001", "private_base_url": "http://connector.invalid", "status": "registered", "reachable_routes": map[string]any{"namespace": entry.namespace, "fqdn_domains": []string{entry.domain}}})
		req := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(string(body)))
		req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", entry.id, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/connector-discovery/refresh", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Candidates []policycandidate.Candidate `json:"candidates"`
		Count      int                         `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Count != 1 || len(response.Candidates) != 1 || response.Candidates[0].Host != "valid.example.test" {
		t.Fatalf("refresh=%s", rec.Body.String())
	}
	fresh := policycandidate.NewStore()
	if err := fresh.SetPersister(disk); err != nil {
		t.Fatal(err)
	}
	saved, err := fresh.List(ctx, "tenant_lab_001", policycandidate.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Candidates) != 1 || saved.Candidates[0].Host != "valid.example.test" {
		t.Fatalf("saved=%+v", saved)
	}
}
