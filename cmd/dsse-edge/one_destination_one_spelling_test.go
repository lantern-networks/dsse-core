package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// Found on a Windows walk: the same private application appeared as two uncovered destinations,
// "10.55.1.30" and "::ffff:10.55.1.30", depending on which program opened the connection.
func TestAnIPv4DestinationHasOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:10.55.1.30":          "10.55.1.30",
		"::FFFF:192.0.2.7":           "192.0.2.7",
		"10.55.1.30":                 "10.55.1.30",
		"2001:db8::1":                "2001:db8::1",
		"wiki.org-01.fleet.internal": "wiki.org-01.fleet.internal",
		"":                           "",
	} {
		if got := ipv4HostWithoutMapping(in); got != want {
			t.Errorf("%q became %q, want %q", in, got, want)
		}
	}
}

// Found on the second Windows walk: the observation inventory listed a flow by its address, "uncovered", while
// the access log showed the same flow allowed by a rule written for the application's name.
func TestAnObservedFlowIsRecordedUnderTheNameTheDecisionUsed(t *testing.T) {
	if got := observedDestinationFor("10.55.1.30", model.DecisionRequest{FQDN: "wiki.corp.example."}); got != "wiki.corp.example" {
		t.Fatalf("recorded under %q, want the name", got)
	}
	if got := observedDestinationFor("10.55.1.30", model.DecisionRequest{}); got != "10.55.1.30" {
		t.Fatalf("with no name known, recorded under %q", got)
	}
	if got := observedDestinationFor("wiki.corp.example", model.DecisionRequest{FQDN: "other.example"}); got != "wiki.corp.example" {
		t.Fatalf("a name the device sent was replaced by %q", got)
	}
}
