package vlan

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestBuildVLANBoundaryExport(t *testing.T) {
	objects := []model.VLANObject{
		{ID: "o1", Class: "unmanaged_endpoint", CIDRs: []string{"10.10.0.0/24"}},
		{ID: "o2", Class: "server", CIDRs: []string{"10.20.0.0/24", "10.21.0.0/24"}},
		{ID: "o3", Class: "managed_endpoint", CIDRs: []string{"10.1.0.0/24"}},
	}
	policies := []model.VLANBoundaryPolicy{
		{ID: "p1", SourceClass: "unmanaged_endpoint", DestClass: "server", ServiceFamily: "smb", Ports: []int{445}, Mode: "deny", Status: "active"},
		{ID: "p2", SourceClass: "unmanaged_endpoint", DestClass: "managed_endpoint", ServiceFamily: "rdp", Ports: []int{3389}, Mode: "warn", Status: "active"},
		{ID: "p3", SourceClass: "unmanaged_endpoint", DestClass: "management", ServiceFamily: "ssh", Mode: "deny", Status: "active"},  // no management object -> no rule
		{ID: "p4", SourceClass: "server", DestClass: "managed_endpoint", ServiceFamily: "winrm", Mode: "observe", Status: "disabled"}, // disabled -> skipped
	}
	exp := BuildBoundaryExport(objects, policies, "2026-06-17T00:00:00Z")
	if exp.RuleCount != 2 {
		t.Fatalf("rule count = %d, want 2 (p3 no dest object, p4 disabled)", exp.RuleCount)
	}
	r0 := exp.Rules[0] // p1
	if r0.PolicyID != "p1" || r0.Action != "deny" || len(r0.DestCIDRs) != 2 || r0.SourceCIDRs[0] != "10.10.0.0/24" {
		t.Fatalf("p1 rule wrong: %+v", r0)
	}
	if exp.Rules[1].PolicyID != "p2" || exp.Rules[1].Action != "log_alert" {
		t.Fatalf("p2 rule should map warn->log_alert: %+v", exp.Rules[1])
	}
}

func TestStoreGetAndDeleteObject(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertObject(model.VLANObject{ID: "net-1", Name: "Tokyo", Class: "server", CIDRs: []string{"10.20.0.0/16"}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	o, ok := s.GetObject("net-1")
	if !ok || o.Name != "Tokyo" || len(o.CIDRs) != 1 {
		t.Fatalf("GetObject wrong: %+v ok=%v", o, ok)
	}
	if _, ok := s.GetObject("missing"); ok {
		t.Fatal("GetObject must be false for a missing id")
	}
	g := s.ConfigGeneration()
	if !s.DeleteObject("net-1") {
		t.Fatal("DeleteObject must report true for an existing id")
	}
	if _, ok := s.GetObject("net-1"); ok {
		t.Fatal("object must be gone after delete")
	}
	if s.ConfigGeneration() <= g {
		t.Fatal("delete must bump the generation")
	}
	if s.DeleteObject("net-1") {
		t.Fatal("DeleteObject must report false for an absent id")
	}
}
