package main

import (
	"strings"
	"testing"
)

// ★★★ THE TOKEN IS ONE-TIME; THE CONFIGURATION IS NOT. A connector's doors used to be whatever its enrolment
// token carried, frozen on the day somebody pressed "Add connector". This is the answer it re-reads.
func TestTheConnectorProfileCarriesEveryDoor(t *testing.T) {
	regions := func(string) []regionEndpoint {
		return []regionEndpoint{
			{Region: "region-a", Endpoint: "https://a.example"},
			{Region: "region-b", Endpoint: "https://b.example:10443"},
		}
	}
	p := connectorProfileFor("tenant_default", "tokyo-dc", "https://fallback.example", regions)
	if p.SchemaVersion != "connector_profile.v1" {
		t.Fatalf("schema: %q", p.SchemaVersion)
	}
	if len(p.EdgeEndpoints) != 2 || p.EdgeEndpoints[0] != "region-a=https://a.example" {
		t.Fatalf("endpoints: %v", p.EdgeEndpoints)
	}
	if p.Site != "tokyo-dc" || p.TenantID != "tenant_default" {
		t.Fatalf("identity: site=%q tenant=%q", p.Site, p.TenantID)
	}
	if !strings.Contains(p.Note, "survives losing a region") {
		t.Fatalf("the note must say what the list MEANS for the estate behind this connector: %q", p.Note)
	}
}

// ★ ONE DOOR IS NOT A LIST, AND SAYING SO IS THE POINT. A connector reading this is the party that finds out
// first when a region goes away.
func TestTheConnectorProfileSaysWhenThereIsOnlyOneDoor(t *testing.T) {
	one := connectorProfileFor("t", "s", "https://only.example", func(string) []regionEndpoint { return nil })
	if len(one.EdgeEndpoints) != 1 {
		t.Fatalf("a deployment with no region map still answers with the address it knows: %v", one.EdgeEndpoints)
	}
	if !strings.Contains(one.Note, "unreachable until it comes back") {
		t.Fatalf("one door has a consequence and the note must carry it: %q", one.Note)
	}

	none := connectorProfileFor("t", "s", "", func(string) []regionEndpoint { return nil })
	if len(none.EdgeEndpoints) != 0 {
		t.Fatalf("nothing known must be answered as nothing, not invented: %v", none.EdgeEndpoints)
	}
	if !strings.Contains(none.Note, "has not been told any address") {
		t.Fatalf("a deployment that knows no address must say so: %q", none.Note)
	}
}
