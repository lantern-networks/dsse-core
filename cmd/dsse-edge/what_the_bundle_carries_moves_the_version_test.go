package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

// ★★★ EVERY STORE THE BUNDLE CARRIES MOVES THE BUNDLE'S VERSION (2026-09-02, the sixth and seventh time this
// was needed, both measured failing on a live deployment).
//
// An Edge applies a bundle only when its version is newer. A store the version does not count changes the
// bundle's CONTENTS without changing its VERSION, so no Edge re-pulls: an ADD appears to work because
// somebody restarted the fleet, and a DELETION never arrives at all. The comments beside the sum record the
// directory, the licence, the rules, the assets, the internal CAs and the tenant registry each learning this
// separately.
//
// Today it was the identity-provider registry — which reached the Edges only because the roll that shipped it
// restarted them — and the grants, which sat on the authority while every Edge listed none, indefinitely.
// That last one would have made a REVOCATION reach nobody, which is the reason grants are carried at all.
func TestWhatTheBundleCarriesMovesTheVersion(t *testing.T) {
	body, err := os.ReadFile("admin_policy_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	sum := string(body)
	for _, carried := range []struct{ what, needs string }{
		{"the identity-provider registry", "theIdPRegistry.Load(); reg != nil"},
		{"the grants the fleet has approved", "theGrantStore.Load(); grants != nil"},
	} {
		if !strings.Contains(sum, carried.needs) {
			t.Errorf("%s is carried in the bundle and is not in its version sum — an Edge applies a bundle "+
				"only when the version is newer, so a change to it reaches nobody until something restarts "+
				"the fleet, and a deletion reaches nobody at all", carried.what)
		}
	}

	// And the stores actually move when they change — a ConfigGeneration that never advances is the same
	// outage with a method on it.
	reg := idpregistry.NewStore()
	before := reg.ConfigGeneration()
	if _, err := reg.Upsert(idpregistry.Connection{
		IdPID: "idp", TenantID: "t1", Type: "oidc", Issuer: "https://i.example",
		AuthorizationEndpoint: "https://i.example/a", TokenEndpoint: "https://i.example/t", ClientID: "c",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if reg.ConfigGeneration() == before {
		t.Error("registering an identity provider did not move the registry's version")
	}
	before = reg.ConfigGeneration()
	if _, err := reg.Delete("t1", "idp"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if reg.ConfigGeneration() == before {
		t.Error("DELETING an identity provider did not move the version — the deletion would never reach an Edge")
	}

	now := time.Now().UTC()
	grants := grantstore.NewStore()
	before = grants.ConfigGeneration()
	if _, err := grants.Mint(grantstore.Grant{GrantID: "g1", TenantID: "t1", UserID: "u", IdPID: "idp"},
		time.Hour, now); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if grants.ConfigGeneration() == before {
		t.Error("minting a grant did not move the grant store's version")
	}
	before = grants.ConfigGeneration()
	if !grants.Revoke("g1") {
		t.Fatal("revoke")
	}
	if grants.ConfigGeneration() == before {
		t.Error("REVOKING a grant did not move the version — the revocation would reach no other Edge, which " +
			"is the one thing carrying grants exists for")
	}
}
