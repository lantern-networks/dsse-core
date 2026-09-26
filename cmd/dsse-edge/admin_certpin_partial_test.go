package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type certPinPartialFixture struct {
	tenant     string
	candidate  policycandidate.Candidate
	candidates *policycandidate.Store
	assets     *assetcatalog.Store
	rules      *policyrule.Store
	writer     *logs.Writer
	engine     *edgeplane.NetworkExtensionLabTLSInterception
	applies    int
	handler    http.Handler
}

func newCertPinPartialFixture(t *testing.T, candidateP, assetP, ruleP blobstore.Persister, source string) *certPinPartialFixture {
	t.Helper()
	f := &certPinPartialFixture{tenant: testEvaluator().PolicyBundle.TenantID, candidates: policycandidate.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore()}
	for _, e := range []error{f.candidates.SetPersister(candidateP), f.assets.SetPersister(assetP), f.rules.SetPersister(ruleP)} {
		if e != nil {
			t.Fatal(e)
		}
	}
	var e error
	f.candidate, e = f.candidates.AddManualCertPinBypass(context.Background(), f.tenant, "manual.example", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "reviewer", TenantID: f.tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "pin-session", TenantID: f.tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "pin-csrf"}})
	f.writer, e = logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.writer.Close() })
	f.engine = edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	// Match the current public node-wide apply contract. Tenant-specific engine
	// acceptance belongs to the separate interception migration.
	apply := func(tenant string) {
		f.engine.SetBypassHosts(policyrule.EgressBypassFQDNs(tenant, f.rules.List(tenant, policyrule.PlaneEgress), f.assets))
	}
	f.handler = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: f.writer, AdminAuth: auth, OperatorTenantID: "operator", PolicyCandidateStore: f.candidates, RuleStore: f.rules, AssetStore: f.assets, NetworkExtensionLabTLS: f.engine, ConfigSourceURL: source, ApplyMaterializedCertPinBypass: func(tenant string) { f.applies++; apply(tenant) }})
	f.applies = 0
	return f
}
func (f *certPinPartialFixture) post(path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "admin_session", Value: "pin-session"})
	r.Header.Set("X-CSRF-Token", "pin-csrf")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}
func (f *certPinPartialFixture) inspect(tenant string) bool {
	return f.engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "manual.example", Port: 443})
}

func TestCertPinPartialSaveRetryAndAudit(t *testing.T) {
	for _, pathType := range []string{"manual", "materialize"} {
		for _, stage := range []string{"bypass_endpoint", "bypass_rule"} {
			t.Run(pathType+"/"+stage, func(t *testing.T) {
				cp, ap, rp := &candidateNthPersister{}, &candidateNthPersister{}, &candidateNthPersister{}
				f := newCertPinPartialFixture(t, cp, ap, rp, "")
				path := "/admin/cert-pin-bypass"
				body := `{"host":"manual.example"}`
				if pathType == "materialize" {
					path = "/admin/policy-candidates/" + f.candidate.CandidateID + "/materialize"
					body = `{}`
				}
				fault := ap
				if stage == "bypass_rule" {
					fault = rp
				}
				fault.failAt = fault.calls + 1
				w := f.post(path, body)
				var result map[string]any
				json.Unmarshal(w.Body.Bytes(), &result)
				if w.Code != 500 || result["partial"] != true || result["failed_stage"] != stage || strings.Contains(w.Body.String(), "/private/") {
					t.Fatalf("partial %d %s", w.Code, w.Body)
				}
				if f.applies != 0 || !f.inspect(f.tenant) || len(f.rules.Snapshot()) != 0 {
					t.Fatal("unconfirmed rule was applied")
				}
				saved := policycandidate.NewStore()
				if e := saved.SetPersister(cp); e != nil {
					t.Fatal(e)
				}
				c, found, _ := saved.Get(context.Background(), f.tenant, f.candidate.CandidateID)
				if !found || c.Status != "materialized" {
					t.Fatal("saved earlier step not retained")
				}
				// Retry the exact request, including direct materialization of the already-materialized candidate.
				w = f.post(path, body)
				if w.Code != 200 || f.applies != 1 || f.inspect(f.tenant) {
					t.Fatalf("retry %d %s", w.Code, w.Body)
				}
				if len(f.rules.Snapshot()) != 1 || len(f.assets.ListEndpoints(f.tenant)) != 1 {
					t.Fatal("retry duplicated output")
				}
				reopenedRules := policyrule.NewStore()
				if e := reopenedRules.SetPersister(rp); e != nil || len(reopenedRules.Snapshot()) != 1 {
					t.Fatal("rule persistence", e)
				}
				rows, e := f.writer.ReadJSONL("audit.log.jsonl")
				if e != nil || len(rows) != 4 {
					t.Fatal("audit count", len(rows), e)
				}
				for i, a := range rows {
					if a["actor_user_id"] != "reviewer" || a["tenant_id"] != f.tenant {
						t.Fatal("audit attribution", a)
					}
					want := []string{"partial", "error", "success", "success"}[i]
					if a["result"] != want {
						t.Fatal("audit result", a)
					}
					if i%2 == 0 {
						m := a["metadata"].(map[string]any)
						if m["candidate_saved"] != true || m["rule_state_confirmed"] != (i == 2) || m["policy_materialized"] != (i == 2) || m["local_apply_requested"] != (i == 2) {
							t.Fatal("audit application claim", a)
						}
						if i == 0 && m["failed_stage"] != stage {
							t.Fatal("wrong failed stage")
						}
					}
				}
				raw, _ := json.Marshal(rows)
				for _, secret := range []string{"/private/", "pin-session", "pin-csrf"} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Fatal("private value in audit")
					}
				}
			})
		}
	}
}

func TestCertPinReviewRemovalFailure(t *testing.T) {
	for _, sourced := range []bool{false} {
		t.Run(map[bool]string{false: "local", true: "sourced"}[sourced], func(t *testing.T) {
			cp, ap, rp := &candidateNthPersister{}, &candidateNthPersister{}, &candidateNthPersister{}
			f := newCertPinPartialFixture(t, cp, ap, rp, "")
			if w := f.post("/admin/cert-pin-bypass", `{"host":"manual.example"}`); w.Code != 200 {
				t.Fatal(w.Code)
			}
			path := "/admin/policy-candidates/" + f.candidate.CandidateID + "/review"
			rp.failAt = rp.calls + 1
			beforeApplies := f.applies
			w := f.post(path, `{"decision":"rejected"}`)
			var body map[string]any
			json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != 500 || body["partial"] != true || body["failed_stage"] != "bypass_rule_removal" || f.applies != beforeApplies || f.inspect(f.tenant) {
				t.Fatalf("removal failure %d %s", w.Code, w.Body)
			}
			c, _, _ := f.candidates.Get(context.Background(), f.tenant, f.candidate.CandidateID)
			if c.Status != "rejected" {
				t.Fatal("candidate stage not saved")
			}
			if w = f.post(path, `{"decision":"rejected"}`); w.Code != 200 || !f.inspect(f.tenant) {
				t.Fatalf("cleanup retry %d %s", w.Code, w.Body)
			}
			rows, e := f.writer.ReadJSONL("audit.log.jsonl")
			if e != nil || len(rows) != 6 {
				t.Fatal("audit count", len(rows), e)
			}
			for _, idx := range []int{2, 4} {
				m := rows[idx]["metadata"].(map[string]any)
				if rows[idx]["actor_user_id"] != "reviewer" || m["rule_operation"] != "delete" || m["rule_state_confirmed"] != (idx == 4) || m["policy_materialized"] != false || m["local_apply_requested"] != (idx == 4) {
					t.Fatal("removal audit", rows[idx])
				}
			}
		})
	}
}

type blockedCertPinPersister struct{ entered, release chan struct{} }

func (p *blockedCertPinPersister) Load() ([]byte, error) { return nil, nil }
func (p *blockedCertPinPersister) Save([]byte) error     { close(p.entered); <-p.release; return nil }
func TestCertPinReviewWaitsForInFlightMaterialization(t *testing.T) {
	ap := &blockedCertPinPersister{make(chan struct{}), make(chan struct{})}
	f := newCertPinPartialFixture(t, &candidateNthPersister{}, ap, &candidateNthPersister{}, "")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.post("/admin/cert-pin-bypass", `{"host":"manual.example"}`) }()
	select {
	case <-ap.entered:
	case w := <-done:
		t.Fatalf("registration finished before dependent save: %d %s", w.Code, w.Body)
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not reach dependent save")
	}
	reviewed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		reviewed <- f.post("/admin/policy-candidates/"+f.candidate.CandidateID+"/review", `{"decision":"rejected"}`)
	}()
	select {
	case <-reviewed:
		t.Error("review passed in-flight registration")
	case <-time.After(50 * time.Millisecond):
	}
	close(ap.release)
	if w := <-done; w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	select {
	case w := <-reviewed:
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("review did not finish")
	}
	if !f.inspect(f.tenant) || len(f.rules.Snapshot()) != 0 {
		t.Fatal("revocation lost to registration")
	}
	c, _, _ := f.candidates.Get(context.Background(), f.tenant, f.candidate.CandidateID)
	if c.Status != "rejected" {
		t.Fatal(c.Status)
	}
}

func TestCertPinExistingBypassAfterUnconfirmedRegistration(t *testing.T) {
	rp := &candidateNthPersister{}
	f := newCertPinPartialFixture(t, &candidateNthPersister{}, &candidateNthPersister{}, rp, "")
	path := "/admin/cert-pin-bypass"
	body := `{"host":"manual.example"}`
	if w := f.post(path, body); w.Code != 200 {
		t.Fatal(w.Code)
	}
	rp.failAt = rp.calls + 1
	if w := f.post(path, body); w.Code != 500 || !strings.Contains(w.Body.String(), "existing bypass may still be active") {
		t.Fatal(w.Code, w.Body)
	}
	if f.inspect(f.tenant) || f.applies != 1 {
		t.Fatal("unconfirmed registration changed current bypass")
	}
	if w := f.post(path, body); w.Code != 200 || f.applies != 2 || len(f.rules.Snapshot()) != 1 {
		t.Fatal("retry", w.Code, w.Body)
	}
}
