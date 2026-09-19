package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func dlpStoresForTest(salt string) *dlpConfigStores {
	return &dlpConfigStores{policies: newDLPPolicyObjectStore(), classifiers: newDLPClassifierRuntimeStore(), fingerprints: newDLPFingerprintRuntimeStore(salt), allowlist: newDLPAllowlistRuntimeStore(salt)}
}

func TestDistributedDLPDefinitionsBlockOnTheReceivingEdge(t *testing.T) {
	cp := dlpStoresForTest("authority-salt")
	edge := dlpStoresForTest("different-edge-salt")
	cp.classifiers.SetSpecs("a", []dlp.ClassifierSpec{{Name: "project", Kind: "keyword", Keywords: []string{"PROJECT-ORCHID-SECRET"}}})
	cp.fingerprints.SetDataset("a", "records", []string{"CUSTOMER-7654321"})
	cp.policies.Upsert(model.DLPPolicyObject{ID: "protect", TenantID: "a", Name: "Protect", Identifiers: []string{"credit_card", "project", "records"}, OnMatch: "block", Status: "active"})
	src := configBundleSource{tenantID: "a"}
	targets := configApplyTargets{policyStore: policy.NewStore(nil), dlp: edge}
	b := configBundlePayload{DLP: cp.Snapshot()}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CUSTOMER-7654321") {
		t.Fatal("EDM source value entered distributed configuration")
	}
	var received configBundlePayload
	if err = json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	if _, err = src.apply(received, targets); err != nil {
		t.Fatal(err)
	}
	cfg, _ := newDLPTestConfig(t)
	cfg.DLPPolicies = edge.policies
	cfg.DLPClassifiers = edge.classifiers
	cfg.DLPFingerprints = edge.fingerprints
	dec := model.AccessDecision{ID: "decision", TenantID: "a", Actions: []model.DecisionAction{{Type: "dlp_inspect", Metadata: map[string]any{"dlp_policy_id": "protect"}}}}
	for _, value := range []string{"4111111111111111", "PROJECT-ORCHID-SECRET", "CUSTOMER-7654321"} {
		req := httptest.NewRequest(http.MethodPost, "https://ai.example.test/upload", strings.NewReader(`{"text":"`+value+`"}`))
		req.Header.Set("Content-Type", "application/json")
		hook := installEdgeSWGHTTPEgressDLP(req, cfg, dec)
		sent, err := io.ReadAll(req.Body)
		if !errors.Is(err, dlp.ErrBlocked) || strings.Contains(string(sent), value) {
			t.Fatalf("distributed detector did not stop upload (%s): %v", value, err)
		}
		response := httptest.NewRecorder()
		hook.respondBlocked(response, req)
		if response.Code != 403 {
			t.Fatalf("HTTP %d, want 403", response.Code)
		}
	}
	if _, ok := edge.policies.Get("other", "protect"); ok {
		t.Fatal("policy crossed tenant boundary")
	}
	gen := cp.Generation()
	p, _ := cp.policies.Get("a", "protect")
	p.OnMatch = "observe"
	cp.policies.Upsert(p)
	if cp.Generation() <= gen {
		t.Fatal("policy-only edit cannot wake sync")
	}
	if _, err = src.apply(configBundlePayload{DLP: cp.Snapshot()}, targets); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://ai.example.test/upload", strings.NewReader(`{"text":"4111111111111111"}`))
	req.Header.Set("Content-Type", "application/json")
	installEdgeSWGHTTPEgressDLP(req, cfg, dec)
	if _, err = io.ReadAll(req.Body); err != nil {
		t.Fatalf("policy edit did not reach enforcement: %v", err)
	}
	// An omitted or malformed section retains the accepted policy; an explicit
	// complete empty authority removes it, so deletes cannot leave a stale rule.
	if _, err = src.apply(configBundlePayload{}, targets); err != nil {
		t.Fatal(err)
	}
	if _, ok := edge.policies.Get("a", "protect"); !ok {
		t.Fatal("older authority wiped DLP")
	}
	invalid := cp.Snapshot()
	invalid.Policies["a"]["protect"] = model.DLPPolicyObject{ID: "protect", TenantID: "other", OnMatch: "block", Identifiers: []string{"credit_card"}}
	if _, err = src.apply(configBundlePayload{DLP: invalid}, targets); err == nil {
		t.Fatal("invalid tenant attribution was applied")
	}
	if held, _ := edge.policies.Get("a", "protect"); held.OnMatch != "observe" {
		t.Fatal("rejection changed live enforcement")
	}
	gen = cp.Generation()
	cp.policies.Delete("a", "protect")
	if cp.Generation() <= gen {
		t.Fatal("deletion cannot wake sync")
	}
	if _, err = src.apply(configBundlePayload{DLP: cp.Snapshot()}, targets); err != nil {
		t.Fatal(err)
	}
	if _, ok := edge.policies.Get("a", "protect"); ok {
		t.Fatal("deleted policy survived distribution")
	}
}

func TestDLPDistributionLibraryEditsAndTenantScope(t *testing.T) {
	s := dlpStoresForTest("salt")
	gen := s.Generation()
	s.classifiers.SetSpecs("a", []dlp.ClassifierSpec{{Name: "project", Kind: "keyword", Keywords: []string{"test"}}})
	if s.Generation() <= gen {
		t.Fatal("classifier edit did not advance generation")
	}
	gen = s.Generation()
	s.fingerprints.SetDataset("a", "records", []string{"test-record"})
	if s.Generation() <= gen {
		t.Fatal("dataset edit did not advance generation")
	}
	s.policies.Upsert(model.DLPPolicyObject{ID: "other", TenantID: "b", Identifiers: []string{"credit_card"}, OnMatch: "block"})
	scoped := s.Snapshot().ForTenant("a")
	if len(scoped.Policies) != 0 || len(scoped.Classifiers) != 1 || len(scoped.Datasets) != 1 {
		t.Fatal("scope included another tenant or lost its own library")
	}
	edge := dlpStoresForTest("different")
	if err := edge.Apply(s.Snapshot()); err != nil {
		t.Fatal(err)
	}
	invalid := s.Snapshot()
	invalid.Classifiers["a"] = []dlp.ClassifierSpec{{Name: "bad", Kind: "regex", Pattern: "["}}
	if err := edge.Apply(invalid); err == nil {
		t.Fatal("malformed classifier accepted")
	}
	if !edge.classifiers.ClassifierSetForTenant("a").Has("project") {
		t.Fatal("malformed update erased the accepted classifier")
	}
	invalid = s.Snapshot()
	invalid.Datasets = nil
	if err := edge.Apply(invalid); err == nil {
		t.Fatal("truncated library accepted")
	}
	gen = s.Generation()
	s.classifiers.SetSpecs("a", nil)
	s.fingerprints.RemoveDataset("a", "records")
	if s.Generation() <= gen {
		t.Fatal("library deletion did not advance generation")
	}
	if err := edge.Apply(s.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if edge.classifiers.ClassifierSetForTenant("a").Has("project") || len(edge.fingerprints.DatasetsForTenant("a")) != 0 {
		t.Fatal("deleted library survived distribution")
	}
}
