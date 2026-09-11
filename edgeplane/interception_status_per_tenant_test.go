package edgeplane

import (
	"testing"
	"time"
)

// ★★ THE STATUS ENDPOINT NEVER MENTIONED A TENANT (2026-08-18, measured through the Console as an operator
// inside Northwind, which has its own interception root).
//
// It answered mode=offline, intermediate_cn="Lantern DSSE Interception Issuing CA (tenant_reference_lab)",
// root_cn="Lantern DSSE MSSP Root CA v2" — every field about a different organization's issuer and the
// provider's root, with nothing in the answer saying so. The Console, reading it, printed "this tenant has no
// interception authority of its own" immediately above a card displaying that tenant's own root.
//
// Both halves matter. A screen that is merely wrong gets corrected; a screen that is confidently wrong about
// whose authority decrypts a customer's traffic is the claim this product exists to make correctly.
func TestInterceptionStatusAnswersAboutTheTenantAsked(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Operator", now)
	interception, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(
		[]string{"*"}, func() time.Time { return now }, rootPEM, interPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("offline interception: %v", err)
	}
	interception.SetOfflinePrimaryTenant("tenant_lab")
	nwRoot, nwInter, nwKey, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", nwRoot, nwInter, nwKey); err != nil {
		t.Fatalf("load northwind: %v", err)
	}

	nw := interception.InterceptionIntermediateStatusForTenant("tenant_northwind")
	if nw["mode"] != "own_offline_root" {
		t.Fatalf("Northwind's mode is %v, want own_offline_root: %+v", nw["mode"], nw)
	}
	if got, _ := nw["root_common_name"].(string); got != "Northwind Interception Root" {
		t.Fatalf("Northwind was told its root is %q — the whole defect was answering with somebody else's", got)
	}
	if nw["tenant_id"] != "tenant_northwind" {
		t.Fatalf("the answer does not say who it is about: %+v", nw)
	}

	// ★ THE CONTROL, and it is the one that catches a handler that ignores its argument: a DIFFERENT tenant
	// must get a DIFFERENT answer. Asserting only Northwind's would pass for the broken version on any node
	// where Northwind happened to be the node's own tenant.
	lab := interception.InterceptionIntermediateStatusForTenant("tenant_lab")
	if lab["mode"] != "node_intermediate" {
		t.Fatalf("the primary tenant's mode is %v, want node_intermediate: %+v", lab["mode"], lab)
	}
	if lab["root_common_name"] == nw["root_common_name"] {
		t.Fatalf("two organizations were told the same root %v — the answer does not depend on who asked",
			lab["root_common_name"])
	}

	// A tenant with nothing of its own is told its traffic is refused, not that it is inspected by somebody.
	none := interception.InterceptionIntermediateStatusForTenant("tenant_acme")
	if none["mode"] != "none" {
		t.Fatalf("a tenant with no authority got mode %v: %+v", none["mode"], none)
	}
	if d, _ := none["detail"].(string); d == "" {
		t.Fatal("the answer gives no reason, so a screen reading it has to invent one — which is how this broke")
	}

	// Revocation wins over everything else: it is the state where saying "inspected under its own root" would
	// be exactly backwards.
	if _, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "key compromise drill"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := interception.InterceptionIntermediateStatusForTenant("tenant_northwind"); got["mode"] != "revoked" {
		t.Fatalf("a revoked tenant reports mode %v: %+v", got["mode"], got)
	}
}
