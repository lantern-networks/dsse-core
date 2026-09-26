package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestAuthoredRuleHTTPPersistenceCompilationAndAudit(t *testing.T) {
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &ruleAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "rules.json")}}
	s := policyrule.NewStore()
	s.SetPersister(p)
	policies := policy.NewStore(nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: newAdminAuthStore(), RuleStore: s, PolicyStore: policies})
	body := `{"id":"durable-rule","plane":"egress","name":"private-rule-name","source":["*"],"destination":["*"],"action":{"access":"deny"}}`
	call := func(method, path, data string, status int) {
		t.Helper()
		r := doAdmin(t, h, method, path, data)
		if r.Code != status {
			t.Fatalf("%s = %d want %d: %s", method, r.Code, status, r.Body)
		}
		if strings.Contains(r.Body.String(), "private-runtime-location") {
			t.Fatal("private storage error exposed")
		}
	}
	assertCount := func(n int) {
		t.Helper()
		if len(s.Snapshot()) != n || len(policies.RuntimeEvaluator(testEvaluator()).Policies) != n {
			t.Fatal("stored and compiled rules differ", s.Snapshot(), policies.RuntimeEvaluator(testEvaluator()).Policies)
		}
	}
	p.fail.Store(true)
	call("POST", "/admin/rules", body, 500)
	assertCount(0)
	p.fail.Store(false)
	call("POST", "/admin/rules", body, 200)
	assertCount(1)
	p.fail.Store(true)
	call("POST", "/admin/rules", strings.Replace(body, "private-rule-name", "changed-name", 1), 500)
	assertCount(1)
	if s.Snapshot()[0].Name != "private-rule-name" {
		t.Fatal("failed edit adopted")
	}
	call("DELETE", "/admin/rules/durable-rule", "", 500)
	assertCount(1)
	p.fail.Store(false)
	call("DELETE", "/admin/rules/durable-rule", "", 200)
	assertCount(0)
	call("DELETE", "/admin/rules/durable-rule", "", 404)
	rows := readConnectorManagementAudits(t, w)
	domain, failed := 0, 0
	for _, a := range rows {
		if a.EventType != "admin_authored_rule_changed" {
			continue
		}
		domain++
		if a.TenantID != "tenant_lab_001" || stringPtrValue(a.TargetID) != "durable-rule" || stringPtrValue(a.ActorUserID) == "" || a.Metadata["rule_sha256"] == nil {
			t.Fatalf("bad rule audit: %+v", a)
		}
		if stringPtrValue(a.Result) == "persistence_unconfirmed" {
			failed++
		}
	}
	if domain != 6 || failed != 3 {
		t.Fatal("audit counts", domain, failed)
	}
	raw, _ := json.Marshal(rows)
	for _, private := range []string{"private-rule-name", "changed-name", "private-runtime-location"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("audit leaks", private)
		}
	}
}

func TestAuthoredRuleSyncRetriesSameGenerationAfterSaveFailure(t *testing.T) {
	s := policyrule.NewStore()
	p := &ruleAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "rules.json")}}
	s.SetPersister(p)
	old, err := s.Upsert(policyrule.Rule{ID: "retained", TenantID: "tenant_lab_001", Name: "old", Plane: policyrule.PlaneEgress, Source: []string{"*"}, Destination: []string{"*"}, Action: policyrule.Action{Access: policyrule.AccessAllow}})
	if err != nil {
		t.Fatal(err)
	}
	next := old
	next.Name = "new"
	p.fail.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls, compiled atomic.Int32
	status := &configBundleSyncStatus{}
	checks := make(chan bool, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			checks <- failed && reflect.DeepEqual(s.Snapshot(), []policyrule.Rule{old}) && compiled.Load() == 0
			p.fail.Store(false)
		}
		if n == 4 {
			status.mu.RLock()
			ok := status.haveApplied && status.lastAppliedGeneration == 31
			status.mu.RUnlock()
			checks <- ok && reflect.DeepEqual(s.Snapshot(), []policyrule.Rule{next}) && compiled.Load() == 1
			cancel()
		}
		json.NewEncoder(w).Encode(configBundlePayload{Generation: 31, Epoch: "rule-retry", Rules: &authoredRuleBundle{Rules: []policyrule.Rule{next}}})
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: "tenant_lab_001", url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), rules: s, onRulesApplied: func() { compiled.Add(1) }})
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("same-generation retry/compile failed")
	}
	reload := policyrule.NewStore()
	if err := reload.SetPersister(p); err != nil || !reflect.DeepEqual(reload.Snapshot(), s.Snapshot()) {
		t.Fatal("retry not durable", err)
	}
}

type ruleAuditPersister struct {
	base blobstore.FilePersister
	fail atomic.Bool
}

func (p *ruleAuditPersister) Load() ([]byte, error) { return p.base.Load() }
func (p *ruleAuditPersister) Save(b []byte) error {
	if p.fail.Load() {
		return errors.New("private-runtime-location failure")
	}
	return p.base.Save(b)
}
