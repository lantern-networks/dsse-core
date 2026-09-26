package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Use the authored-rule selection used by the current public applier: even a materialized candidate is only history
// until its authored rule exists. Deleting the rule does not require erasing history.
func TestCertPinCandidateStatusRequiresAuthoredRule(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := policycandidate.NewStore()
	assets := assetcatalog.NewStore()
	rules := policyrule.NewStore()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	apply := func(string) {
		engine.SetBypassHosts(policyrule.EgressBypassFQDNs("acme", rules.List("acme", policyrule.PlaneEgress), assets))
	}
	c, err := store.ObserveCertPinFailure(ctx, "acme", "pinned.example", "pinned.example", 443, "interception_handshake_rejected", now)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		apply("")
		for _, tenant := range []string{"acme"} {
			expect := want
			if tenant == "other" {
				expect = true
			}
			if got := engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "pinned.example", Port: 443}); got != expect {
				t.Fatalf("%s inspects=%v want %v", tenant, got, expect)
			}
		}
	}
	check(true)
	if _, ok, err := store.Review(ctx, "acme", c.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); err != nil || !ok {
		t.Fatal(ok, err)
	}
	check(true)
	c, ok, err := store.Materialize(ctx, "acme", c.CandidateID, false, now)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	check(true)
	if err := emitCertPinBypassRule(assets, rules, c); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err := rules.Delete("acme", "certpin-rule-"+c.CandidateID); err != nil {
		t.Fatal(err)
	}
	check(true)
	history, ok, err := store.Get(ctx, "acme", c.CandidateID)
	if err != nil || !ok || history.Status != "materialized" {
		t.Fatal(history, ok, err)
	}
}
