package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func reqTo(dst string) model.DecisionRequest {
	return model.DecisionRequest{Destination: dst, ServiceFamily: "ssh"}
}

func TestDeclaredInternalNetworksFromConnectors(t *testing.T) {
	got := declaredInternalNetworksFrom([]connectorRegistrationView{
		{CIDRs: []string{"10.0.0.0/8", " 192.168.5.0/24 "}, FQDNDomains: []string{"corp.example.com"}},
		// A second connector at the same site: overlapping routes must not be duplicated into the declaration.
		{CIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"}, FQDNDomains: []string{"CORP.EXAMPLE.COM", "db.internal.test"}},
		{CIDRs: []string{"", "   "}, FQDNDomains: []string{""}},
	})
	if len(got.CIDRs) != 3 {
		t.Fatalf("CIDRs = %v, want 3 deduped entries", got.CIDRs)
	}
	if len(got.Domains) != 2 {
		t.Fatalf("Domains = %v, want 2 (case-insensitively deduped)", got.Domains)
	}
	// The declaration must actually work as a locality input, not just look right.
	if decision.ClassifyDestinationLocality(reqTo("192.168.5.9"), got) != decision.LocalityInternal {
		t.Fatal("a declared CIDR must classify as internal")
	}
}

func TestNoConnectorsMeansNoDeclarationNotAWildcard(t *testing.T) {
	got := declaredInternalNetworksFrom(nil)
	if !got.Empty() {
		t.Fatalf("no connectors must yield an empty declaration, got %+v", got)
	}
	// And an empty declaration must leave public addresses public — an empty CIDR list must never read as
	// "match everything", which would put the whole internet back on the lateral plane.
	if decision.ClassifyDestinationLocality(reqTo("20.27.177.113"), got) != decision.LocalityPublic {
		t.Fatal("an empty declaration must not make public addresses internal")
	}
	// The private floor still applies with nothing declared.
	if decision.ClassifyDestinationLocality(reqTo("192.168.100.10"), got) != decision.LocalityInternal {
		t.Fatal("private address space is internal with or without a declaration")
	}
}
