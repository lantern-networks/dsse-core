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
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestAdminCandidateSaveFailureStopsDependentChanges(t *testing.T) {
	for _, op := range []string{"upsert", "review", "manual", "manual_second_save", "materialize"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			tenant := testEvaluator().PolicyBundle.TenantID
			now := time.Now()
			s := policycandidate.NewStore()
			p := &candidateNthPersister{}
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			cand, e := s.ObserveCertPinFailure(ctx, tenant, "named.example", "named.example", 443, "rejected", now)
			if e != nil {
				t.Fatal(e)
			}
			if op == "materialize" {
				if _, _, e = s.Review(ctx, tenant, cand.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); e != nil {
					t.Fatal(e)
				}
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "reviewer", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "candidate-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "candidate-csrf"}})
			writer, e := logs.NewWriter(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			assets := assetcatalog.NewStore()
			rules := policyrule.NewStore()
			engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
			apply := func(tenant string) {
				engine.SetBypassHosts(policyrule.EgressBypassFQDNs(tenant, rules.List(tenant, policyrule.PlaneEgress), assets))
			}
			applies := 0
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", PolicyCandidateStore: s, RuleStore: rules, AssetStore: assets, NetworkExtensionLabTLS: engine, ApplyMaterializedCertPinBypass: func(tenant string) { applies++; apply(tenant) }})
			applies = 0
			path := "/admin/policy-candidates/" + cand.CandidateID + "/review"
			body := `{"decision":"approved"}`
			switch op {
			case "manual", "manual_second_save":
				path = "/admin/cert-pin-bypass"
				body = `{"host":"manual.example"}`
			case "materialize":
				path = "/admin/policy-candidates/" + cand.CandidateID + "/materialize"
				body = `{}`
			case "upsert":
				path = "/admin/policy-candidates"
				cand.Status = "rejected"
				b, _ := json.Marshal(cand)
				body = string(b)
			}
			call := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "candidate-session"})
				r.Header.Set("X-CSRF-Token", "candidate-csrf")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			p.failAt = p.calls + 1
			if op == "manual_second_save" {
				p.failAt++
			}
			before, _ := s.List(ctx, tenant, policycandidate.ListOptions{})
			old, _ := json.Marshal(before)
			w := call()
			wantStatus := http.StatusServiceUnavailable
			if op == "manual_second_save" {
				wantStatus = http.StatusInternalServerError
			}
			if w.Code != wantStatus || strings.Contains(w.Body.String(), "/private/") {
				t.Fatalf("unconfirmed save %d %s", w.Code, w.Body)
			}
			if applies != 0 || len(rules.Snapshot()) != 0 || len(assets.ListEndpoints(tenant)) != 0 {
				t.Fatal("failed candidate save reached dependent stores/runtime")
			}
			after, _ := s.List(ctx, tenant, policycandidate.ListOptions{})
			b, _ := json.Marshal(after)
			if op == "manual_second_save" {
				id := policycandidate.CertPinCandidateID("manual.example", "", 443, "operator_manual_add")
				c, found, _ := s.Get(ctx, tenant, id)
				if !found || c.Status != "approved" {
					t.Fatal("confirmed first step missing")
				}
			} else if !bytes.Equal(old, b) {
				t.Fatal("failed candidate save changed live")
			}
			audit, e := writer.ReadJSONL("audit.log.jsonl")
			failureCount := 1
			if op == "manual_second_save" {
				failureCount = 2
			}
			if e != nil || len(audit) != failureCount || audit[failureCount-1]["result"] != "error" {
				t.Fatal("failed write audit", audit, e)
			}
			if w = call(); w.Code != 200 {
				t.Fatalf("retry %d %s", w.Code, w.Body)
			}
			shouldBypass := op == "manual" || op == "manual_second_save" || op == "materialize"
			host := "named.example"
			if strings.HasPrefix(op, "manual") {
				host = "manual.example"
			}
			for _, owner := range []string{tenant} {
				inspect := engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: owner, Host: host, Port: 443})
				if inspect == (shouldBypass && owner == tenant) {
					t.Fatal("wrong tenant interception", owner, inspect)
				}
			}
			fresh := policycandidate.NewStore()
			if e = fresh.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			live, _ := s.List(ctx, tenant, policycandidate.ListOptions{})
			restored, _ := fresh.List(ctx, tenant, policycandidate.ListOptions{})
			x, _ := json.Marshal(live)
			y, _ := json.Marshal(restored)
			if !bytes.Equal(x, y) {
				t.Fatal("candidate restart mismatch")
			}
			audit, e = writer.ReadJSONL("audit.log.jsonl")
			if e != nil || len(audit) != failureCount+2 {
				t.Fatal("audit count", len(audit), e)
			}
			for i, a := range audit {
				want := "success"
				if i < failureCount {
					want = "error"
				}
				if failureCount == 2 && i == 0 {
					want = "partial"
				}
				if a["result"] != want || a["tenant_id"] != tenant {
					t.Fatal("audit mismatch", a)
				}
				if a["event_type"] == "admin_config_change" && a["actor_user_id"] != "reviewer" {
					t.Fatal("missing actor", a)
				}
			}
			raw, _ := json.Marshal(audit)
			for _, secret := range []string{"/private/candidate-state", "candidate-session", "candidate-csrf"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("secret in audit")
				}
			}
		})
	}
}
