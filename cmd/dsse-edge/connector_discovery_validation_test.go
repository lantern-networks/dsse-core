package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectorDiscoveryRefreshSkipsInvalidNamespacePublicBaseline(t *testing.T) {
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
	// A storage failure still interrupts refresh and is not treated like invalid input.
	rejected := &candidateNthPersister{failAt: 1}
	if err := candidates.SetPersister(rejected); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/connector-discovery/refresh", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "/private/") {
		t.Fatalf("rejected save: %d %s", rec.Code, rec.Body.String())
	}

}
