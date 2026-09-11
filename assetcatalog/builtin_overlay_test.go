package assetcatalog

import (
	"reflect"
	"testing"
)

func TestBuiltInCatalogOverlay(t *testing.T) {
	s := NewStore()
	s.SetBuiltInCatalog(
		[]Endpoint{
			{ID: "bi-ep-openai-0", Alias: "chatgpt.com", Kind: KindNetwork, Address: "chatgpt.com", Category: "ai"},
			{ID: "bi-ep-openai-1", Alias: "api.openai.com", Kind: KindNetwork, Address: "api.openai.com", Category: "ai"},
		},
		[]Group{{ID: "bi-grp-openai", Alias: "openai", StaticMembers: []string{"bi-ep-openai-0", "bi-ep-openai-1"}, Category: "ai"}},
	)
	// A rule's destination = the built-in group -> resolves to its host patterns (tenant-agnostic).
	if got := s.EndpointAddresses("acme", []string{"bi-grp-openai"}); !reflect.DeepEqual(got, []string{"api.openai.com", "chatgpt.com"}) {
		t.Fatalf("built-in group addresses = %v, want the patterns", got)
	}
	// Visible in lists, flagged built-in.
	var found bool
	for _, g := range s.ListGroups("acme") {
		if g.ID == "bi-grp-openai" {
			found = g.BuiltIn
		}
	}
	if !found {
		t.Fatalf("built-in group should appear in ListGroups with BuiltIn=true")
	}
	// Not deletable.
	grpDeleted, _ := s.DeleteGroup("acme", "bi-grp-openai")
	epDeleted, _ := s.DeleteEndpoint("acme", "bi-ep-openai-0")
	if grpDeleted || epDeleted {
		t.Fatalf("built-in catalog entries must not be deletable")
	}
}

// TestBuiltInServices: the shipped well-known services are unioned into ListServices for any tenant, marked
// BuiltIn, and a tenant-authored service with the same alias shadows the built-in (no duplicate).
func TestBuiltInServices(t *testing.T) {
	s := NewStore()
	s.SetBuiltInServices(BuiltInServices())

	svcs := s.ListServices("t1")
	if len(svcs) < 15 {
		t.Fatalf("expected the shipped well-known services in ListServices, got %d", len(svcs))
	}
	var ssh *Service
	for i := range svcs {
		if svcs[i].Alias == "SSH" {
			ssh = &svcs[i]
		}
	}
	if ssh == nil {
		t.Fatal("SSH missing from built-in services")
	}
	if !ssh.BuiltIn || len(ssh.Ports) != 1 || ssh.Ports[0].Protocol != "tcp" || ssh.Ports[0].Port != 22 {
		t.Fatalf("SSH built-in wrong: %+v", ssh)
	}

	// A tenant-authored "SSH" shadows the built-in (single entry, tenant's port).
	if _, err := s.UpsertService(Service{TenantID: "t1", Alias: "SSH", Ports: []PortProto{{Protocol: "tcp", Port: 2222}}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	n, port := 0, 0
	for _, sv := range s.ListServices("t1") {
		if sv.Alias == "SSH" {
			n++
			port = sv.Ports[0].Port
		}
	}
	if n != 1 || port != 2222 {
		t.Fatalf("tenant SSH must shadow the built-in (count=%d port=%d)", n, port)
	}
	// Another tenant still sees the built-in SSH (22).
	for _, sv := range s.ListServices("t2") {
		if sv.Alias == "SSH" && sv.Ports[0].Port != 22 {
			t.Fatalf("t2 should see built-in SSH:22, got %d", sv.Ports[0].Port)
		}
	}
}
