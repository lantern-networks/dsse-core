package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressServiceHTTPPreviewAndAdmission(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	a := assetcatalog.NewStore()
	if e := a.SetPersister(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}); e != nil {
		t.Fatal(e)
	}
	_, err := a.UpsertEndpoint(assetcatalog.Endpoint{TenantID: tenant, ID: "dest", Kind: assetcatalog.KindNetwork, Address: "service.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	_, err = rules.Upsert(policyrule.Rule{TenantID: tenant, ID: "test-service", Plane: policyrule.PlaneEgress, Priority: 1, Source: []string{"*"}, Destination: []string{"dest"}, ServiceID: "svc", Action: policyrule.Action{Access: policyrule.AccessAllow}})
	if err != nil {
		t.Fatal(err)
	}
	ps := policy.NewStore(nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, AdminAuth: newAdminAuthStore(), AssetStore: a, RuleStore: rules, PolicyStore: ps})
	call := func(method, path, body string, status int) string {
		t.Helper()
		r := doAdmin(t, h, method, path, body)
		if r.Code != status {
			t.Fatalf("%s %s=%d %s", method, path, r.Code, r.Body)
		}
		return r.Body.String()
	}
	check := func(tcp bool, unresolved bool) {
		t.Helper()
		body := call("GET", "/admin/effective-policy?destination=service.invalid", "", 200)
		var preview effectivePolicyResponse
		if err := json.Unmarshal([]byte(body), &preview); err != nil {
			t.Fatal(err)
		}
		got := strings.HasPrefix(preview.WinnerPolicyID, "rule-egress-test-service")
		if got != tcp {
			t.Fatalf("preview=%s want match=%v", body, tcp)
		}
		req := model.DecisionRequest{TenantID: tenant, ActorType: "human", FQDN: "service.invalid", SNI: "service.invalid", Protocol: "tcp", DestinationPort: 443, ServiceFamily: "https"}
		ev := ps.RuntimeEvaluator(testEvaluator())
		if strings.HasPrefix(ev.ExplainDecision(req).WinnerPolicyID, "rule-egress-test-service") != tcp {
			t.Fatal("runtime differs")
		}
		var list effectiveEgressRuleListResponse
		body = call("GET", "/admin/egress-effective-rules", "", 200)
		if err := json.Unmarshal([]byte(body), &list); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range list.Rules {
			if r.Rule != nil && r.Rule.ID == "test-service" {
				found = true
				if r.ServiceUnresolved != unresolved {
					t.Fatalf("warning=%v", r)
				}
			}
		}
		if !found {
			t.Fatal("authored rule disappeared")
		}
	}
	check(false, true)
	body := call("POST", "/admin/assets/services", `{"id":"svc","ports":[{"protocol":" TCP ","port":443}]}`, 200)
	if !strings.Contains(body, `"protocol":"tcp"`) {
		t.Fatal(body)
	}
	check(true, false)
	call("POST", "/admin/assets/services", `{"id":"svc","ports":[{"protocol":"sctp","port":443}]}`, 400)
	check(true, false)
	call("POST", "/admin/assets/services", `{"id":"svc","ports":[{"protocol":"udp","port":443},{"protocol":"tcp","port":22}]}`, 200)
	check(false, false)
	call("DELETE", "/admin/assets/services/svc", "", 200)
	check(false, true)
}
