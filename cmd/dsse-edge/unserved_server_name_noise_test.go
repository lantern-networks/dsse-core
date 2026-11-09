package main

import "testing"

func TestAnUnservedNameIsWorthALineOnlyWhereOrganizationNamesAreServed(t *testing.T) {
	if unservedServerNameSaysSomething("agents.region-b.example.test", nil) {
		t.Error("a node serving no organization names logged the deployment's own name as unserved")
	}
	if unservedServerNameSaysSomething("", []string{"agents.acme.example.test"}) {
		t.Error("a probe with no name was logged")
	}
	if !unservedServerNameSaysSomething("agents.region-b.example.test", []string{"agents.acme.example.test"}) {
		t.Error("a device asking for another name, where organization names are served, is no longer said")
	}
}
