package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// ★★★ THE CALL SITES ARE THE TEST (2026-09-02).
//
// A section that is written, tested and never published is exactly the defect this file exists because of:
// the IdP registry was authored against the control plane, the Console said 200, and the Edge answering the
// step-up had an empty list. Go compiles an unused function without complaint, so the assertion has to be
// about who NAMES these — the publisher and the applier — not about what they return.
func TestTheIdPRegistryIsPublishedAndApplied(t *testing.T) {
	for _, c := range []struct{ file, needs, why string }{
		{"admin_policy_routes.go", "idpConnectionBundleSection(",
			"the control plane never puts the registry in the bundle, so no Edge can learn it"},
		{"config_bundle_sync.go", "applyIdPConnectionBundleSection(",
			"an Edge never applies the section, so the bundle carries it and nothing reads it"},
	} {
		body, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		if !strings.Contains(string(body), c.needs) {
			t.Errorf("%s does not call %s — %s", c.file, c.needs, c.why)
		}
	}
}

// An incomplete read is not an absence: an Edge that emptied its registry because the control plane could not
// read its own store would refuse to sign anybody in, anywhere, for every organization.
func TestAnIncompleteReadDoesNotEmptyTheRegistry(t *testing.T) {
	store := idpregistry.NewStore()
	if _, err := store.Upsert(idpregistry.Connection{
		IdPID: "keycloak-lab", TenantID: "tenant_a", Type: "oidc",
		Issuer: "https://idp.example/realms/x", ClientID: "dsse-edge",
		AuthorizationEndpoint: "https://idp.example/realms/x/auth",
		TokenEndpoint:         "https://idp.example/realms/x/token",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, applied := applyIdPConnectionBundleSection(store, &idpConnectionBundle{Complete: false}, nil); applied {
		t.Error("an incomplete read was applied")
	}
	if got := len(store.List("tenant_a")); got != 1 {
		t.Fatalf("the registry was emptied by a read the control plane said it could not complete: %d", got)
	}

	// And a complete read replaces, because that is how a DELETION reaches the fleet.
	if _, applied := applyIdPConnectionBundleSection(store, &idpConnectionBundle{Complete: true}, nil); !applied {
		t.Error("a complete, empty section changed nothing — a deletion would never reach this Edge")
	}
	if got := len(store.List("tenant_a")); got != 0 {
		t.Fatalf("a deletion did not reach this Edge: %d connection(s) remain", got)
	}
}

// ★ EVERY ORGANIZATION'S, not the publishing node's. The mistake this deployment has made repeatedly is
// answering a question about somebody else with an attribute of this node.
func TestTheSectionCarriesEveryOrganization(t *testing.T) {
	store := idpregistry.NewStore()
	for _, tenant := range []string{"tenant_b", "tenant_a"} {
		if _, err := store.Upsert(idpregistry.Connection{
			IdPID: "keycloak-lab", TenantID: tenant, Type: "oidc",
			Issuer: "https://idp.example/realms/" + tenant, ClientID: "dsse-edge",
			AuthorizationEndpoint: "https://idp.example/realms/" + tenant + "/auth",
			TokenEndpoint:         "https://idp.example/realms/" + tenant + "/token",
		}); err != nil {
			t.Fatalf("seed %s: %v", tenant, err)
		}
		if err := store.SetDefault(tenant, "keycloak-lab"); err != nil {
			t.Fatalf("default %s: %v", tenant, err)
		}
	}
	section := idpConnectionBundleSection(store)
	if section == nil || len(section.Connections) != 2 {
		t.Fatalf("the section carries %v, not both organizations", section)
	}
	if section.Defaults["tenant_a"] != "keycloak-lab" || section.Defaults["tenant_b"] != "keycloak-lab" {
		t.Errorf("each organization's chosen provider did not travel: %v", section.Defaults)
	}
	// It arrives whole on an Edge that had nothing.
	edge := idpregistry.NewStore()
	count, applied := applyIdPConnectionBundleSection(edge, section, nil)
	if !applied || count != 2 {
		t.Fatalf("applied=%v count=%d", applied, count)
	}
	if _, ok := edge.Default("tenant_a"); !ok {
		t.Error("the Edge holds the connection and not the choice — a step-up with no required IdP would " +
			"still answer \"no usable IdP for the tenant\"")
	}
}
