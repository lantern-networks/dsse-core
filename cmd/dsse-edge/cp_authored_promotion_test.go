package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/model"
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPostgresAuthoredPromotionCompilesLatestRulesAndAssets(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rp := postgresBlobPersister{db: db, key: "test_authored_promotion_rules"}
	ap := postgresBlobPersister{db: db, key: "test_authored_promotion_assets"}
	for _, p := range []postgresBlobPersister{rp, ap} {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
			t.Fatal(err)
		}
		defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	}
	fresh := func() (*policyrule.Store, *assetcatalog.Store) {
		t.Helper()
		r, s := policyrule.NewStore(), assetcatalog.NewStore()
		if err := r.SetPersister(rp); err != nil {
			t.Fatal(err)
		}
		if err := s.SetPersister(ap); err != nil {
			t.Fatal(err)
		}
		return r, s
	}
	authorR, authorA := fresh()
	rules, assets := fresh()
	policies := policy.NewStore(nil)
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	posture := inspectionposture.NewStore()
	posture.Set(inspectionposture.Posture{Mode: inspectionposture.ModeBypassDefault})
	apply := newTenantInspectionApplier(engine, posture, rules, assets, knownbypass.NewOverrideStore(), func() []knownbypass.Group { return nil }, nil, nil)
	compile := newAuthoredRuleCompiler(testEvaluator().PolicyBundle.TenantID, policies, rules, assets, apply)
	configureAuthoredPromotion(b, rules, assets, compile)
	_ = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: policies, RuleStore: rules, AssetStore: assets, RecompileAuthoredRules: compile})
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial election failed")
	}
	tenant := "tenant_lab_001"
	if _, err := authorA.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Alias: "destination", Kind: assetcatalog.KindNetwork, Address: "new.example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authorR.Upsert(policyrule.Rule{ID: "deny-new", TenantID: tenant, Plane: "egress", Source: []string{"*"}, Destination: []string{"destination"}, Action: policyrule.Action{Access: "deny", Inspection: "inspect"}}); err != nil {
		t.Fatal(err)
	}
	// A lower-priority allow supplies an inspection selection. Deny rules themselves
	// never contribute hosts to the inspection engine.
	if _, err := authorR.Upsert(policyrule.Rule{ID: "inspect-new", TenantID: tenant, Priority: 100, Plane: "egress", Source: []string{"*"}, Destination: []string{"destination"}, Action: policyrule.Action{Access: "allow", Inspection: "inspect"}}); err != nil {
		t.Fatal(err)
	}
	if len(rules.Snapshot()) != 0 {
		t.Fatal("candidate unexpectedly refreshed")
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("promotion failed")
	}
	check := func(host string, matched bool) {
		t.Helper()
		d := policies.RuntimeEvaluator(testEvaluator()).Evaluate(model.DecisionRequest{TenantID: tenant, FQDN: host, Destination: host, DestinationPort: 443, Protocol: "tcp", ServiceFamily: "https"})
		if strings.HasPrefix(d.PolicyID, "rule-egress-deny-new") != matched {
			t.Fatalf("live match for %s = %s", host, d.PolicyID)
		}
		if engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: host, Port: 443}) != matched {
			t.Fatalf("inspection not recompiled for %s", host)
		}
	}
	check("new.example.invalid", true)
	check("unrelated.example.invalid", false)
	// The next authority also picks up address-only changes and rules outside its own tenant.
	b.release()
	a.tick()
	if _, err := authorA.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Alias: "destination", Kind: assetcatalog.KindNetwork, Address: "changed.example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authorR.Upsert(policyrule.Rule{ID: "ew-foreign", TenantID: "foreign", Plane: "east_west", Direction: "outbound", Source: []string{"*"}, Destination: []string{"*"}, Action: policyrule.Action{Access: "deny"}}); err != nil {
		t.Fatal(err)
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("second promotion failed")
	}
	check("new.example.invalid", false)
	check("changed.example.invalid", true)
	if _, ok := decision.MatchedEastWestRule(policies.EffectiveEastWestRules("foreign"), model.DecisionRequest{Destination: "10.0.0.10", Protocol: "tcp", DestinationPort: 445}); !ok {
		t.Fatal("foreign east-west rule not compiled")
	}
	// Bad rules OR catalog rows must not publish leadership or replace the compiled state.
	for _, p := range []postgresBlobPersister{rp, ap} {
		saved, err := p.Load()
		if err != nil {
			t.Fatal(err)
		}
		b.release()
		if err := p.Save([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		b.tick()
		if b.IsLeader() {
			t.Fatal("invalid row advertised leadership", p.key)
		}
		check("changed.example.invalid", true)
		a.tick()
		if !a.IsLeader() {
			t.Fatal("failed promotion stranded lock")
		}
		if err := p.Save(saved); err != nil {
			t.Fatal(err)
		}
		a.release()
		b.tick()
		if !b.IsLeader() {
			t.Fatal("repair did not recover")
		}
	}
	// Deleting the last rule of a non-default tenant must clear its compiled owner too.
	b.release()
	a.tick()
	for _, r := range authorR.Snapshot() {
		if _, err := authorR.Delete(r.TenantID, r.ID); err != nil {
			t.Fatal(err)
		}
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("final promotion failed")
	}
	check("changed.example.invalid", false)
	if len(policies.EffectiveEastWestRules("foreign")) != 0 || len(policies.RuntimeEvaluator(testEvaluator()).Policies) != 0 {
		t.Fatal("deleted rule still enforced")
	}

}

func TestAuthoredPromotionWaitsForCompilationAndPreservesPriorFailure(t *testing.T) {
	e := newPromotionModelElector(&promotionLockModel{})
	entered, resume := make(chan struct{}), make(chan struct{})
	configureAuthoredPromotion(e, policyrule.NewStore(), assetcatalog.NewStore(), func() { close(entered); <-resume })
	done := make(chan struct{})
	go func() { defer close(done); e.tick() }()
	<-entered
	if e.IsLeader() {
		t.Error("authority published before compilation")
	}
	close(resume)
	<-done
	if !e.IsLeader() {
		t.Fatal("compiled authority not published")
	}
	e.release()
	failed := newPromotionModelElector(&promotionLockModel{})
	failed.prepareLeadership = func() error { return errors.New("earlier refresh failed") }
	configureAuthoredPromotion(failed, policyrule.NewStore(), assetcatalog.NewStore(), func() { t.Error("compiled despite prior preparation failure") })
	failed.tick()
	if failed.IsLeader() {
		t.Fatal("earlier preparation failure ignored")
	}
	configureAuthoredPromotion(nil, nil, nil, nil)
}

func TestAuthoredPromotionProductionWiring(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	build := strings.Index(s, "recompileAuthoredRules := newAuthoredRuleCompiler(evaluator.PolicyBundle.TenantID,")
	hook := strings.Index(s, "configureAuthoredPromotion(cpLeaderElectorInstance, ruleStore, assetStore, recompileAuthoredRules)")
	start := strings.Index(s, "cpLeaderElectorInstance.Start()")
	if build < 0 || hook < build || start < hook {
		t.Fatal("authored compiler must be wired before election starts")
	}
	if !strings.Contains(s, "RecompileAuthoredRules:         recompileAuthoredRules,") {
		t.Fatal("server must share the promotion compiler")
	}
}
