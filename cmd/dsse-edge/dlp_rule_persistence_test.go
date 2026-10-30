package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

func testDurableDLPRule(tenant string) model.DLPRule {
	return model.DLPRule{ID: "card-rule", TenantID: tenant, Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"}
}

func TestDLPRuleStoreConfirmedSaveRestartAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	store := newDLPRuleRuntimeStore()
	if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"Acme", "acme"} {
		if err := store.SetRulesContext(context.Background(), tenant, []model.DLPRule{testDurableDLPRule(tenant)}); err != nil {
			t.Fatal(err)
		}
	}
	reloaded := newDLPRuleRuntimeStore()
	if err := reloaded.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.RulesForTenant("Acme")) != 1 || len(reloaded.RulesForTenant("acme")) != 1 {
		t.Fatal("confirmed case-distinct rules did not survive restart")
	}
	if err := reloaded.SetRulesContext(context.Background(), "Acme", nil); err != nil {
		t.Fatal(err)
	}
	again := newDLPRuleRuntimeStore()
	if err := again.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(again.RulesForTenant("Acme")) != 0 || len(again.RulesForTenant("acme")) != 1 {
		t.Fatal("authoritative rule clear crossed tenant or did not survive restart")
	}
}

func TestDLPRuleStoreFailedSaveRetainsAcceptedProtection(t *testing.T) {
	p := &allowlistSaveFixture{}
	s := newDLPRuleRuntimeStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRulesContext(context.Background(), "tenant", []model.DLPRule{testDurableDLPRule("tenant")}); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("save failed")
	if err := s.SetRulesContext(context.Background(), "tenant", nil); err == nil {
		t.Fatal("failed rule clear acknowledged")
	}
	if len(s.RulesForTenant("tenant")) != 1 {
		t.Fatal("failed rule clear changed live enforcement")
	}
	p.err = nil
	if err := s.SetRulesContext(context.Background(), "tenant", nil); err != nil {
		t.Fatal(err)
	}
	if len(s.RulesForTenant("tenant")) != 0 {
		t.Fatal("confirmed rule clear did not apply")
	}
}

func TestDLPRuleReceiverRetriesFailedSaveBeforePublishing(t *testing.T) {
	cp, edge := dlpStoresForTest("authority"), dlpStoresForTest("receiver")
	cp.rules.SetRules("tenant", []model.DLPRule{testDurableDLPRule("tenant")})
	p := &allowlistSaveFixture{err: errors.New("save failed")}
	if err := edge.rules.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := edge.Apply(cp.Snapshot()); err == nil || len(edge.rules.RulesForTenant("tenant")) != 0 {
		t.Fatal("failed receiver save exposed new DLP rule")
	}
	p.err = nil
	if err := edge.Apply(cp.Snapshot()); err != nil {
		t.Fatal(err)
	}
	reloaded := newDLPRuleRuntimeStore()
	if err := reloaded.SetPersister(p); err != nil || len(reloaded.RulesForTenant("tenant")) != 1 {
		t.Fatal("confirmed received rule did not survive restart", err)
	}
	legacy := cp.Snapshot()
	legacy.Rules = nil
	if err := edge.Apply(legacy); err != nil || len(edge.rules.RulesForTenant("tenant")) != 1 {
		t.Fatal("older publisher erased the last accepted DLP rule", err)
	}
	cp.rules.SetRules("tenant", nil)
	if err := edge.Apply(cp.Snapshot()); err != nil || len(edge.rules.RulesForTenant("tenant")) != 0 {
		t.Fatal("authoritative empty rule set did not clear", err)
	}
}
