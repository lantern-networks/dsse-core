package main

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
	"testing"
)

func TestCertPinRuleUsesReviewedName(t *testing.T) {
	assets, rules := assetcatalog.NewStore(), policyrule.NewStore()
	c := policycandidate.Candidate{CandidateID: "observed", TenantID: "own", Source: policycandidate.SourceCertPinningDetection, Host: "203.0.113.7", SNI: "named.example"}
	if err := emitCertPinBypassRule(assets, rules, c); err != nil {
		t.Fatal(err)
	}
	ep, ok := assets.GetEndpoint("own", "certpin-ep-observed")
	if !ok || ep.Address != "named.example" || ep.Source != assetcatalog.SourceCertPin {
		t.Fatal("wrong bypass destination", ep)
	}
	got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets)
	if len(got) != 1 || got[0] != "named.example" {
		t.Fatal("wrong bypass scope", got)
	}
	for _, host := range []string{"*.example", "https://named.example", "2001:db8::1"} {
		c.Host, c.SNI = host, ""
		if err := emitCertPinBypassRule(assets, rules, c); err == nil {
			t.Fatal("invalid target accepted", host)
		}
		ep, _ = assets.GetEndpoint("own", "certpin-ep-observed")
		if ep.Address != "named.example" {
			t.Fatal("invalid target changed existing bypass", ep)
		}
	}
}
