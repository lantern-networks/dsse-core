package main

import (
	"strings"
	"testing"
	"time"
)

// ★★★ EVERY TENANT WAS SHOWN THE PROVIDER'S ROOT AS THE AUTHORITY INTERCEPTING IT (2026-08-18, measured on the
// running lab as an operator inside Northwind — a tenant that HAS its own interception root).
//
// Northwind's certificates page listed "Lantern DSSE MSSP Root CA v2" under interception_root, and did not
// list "Northwind Traders Interception Root 2028" — the certificate that actually signs its traffic. The cause
// is one line of plumbing: InterceptionRootPEM is a single node-wide certificate with no owner, and unowned
// items render for every tenant.
//
// The claim on that screen is the opposite of what the product promises. A customer opens Certificates to
// answer exactly one question — whose authority can read my people's traffic — and was told it was the
// provider's, while their own PKI, which is what the design is built around, was invisible.
func TestATenantSeesItsOwnInterceptionRootAndNotTheProvidersC(t *testing.T) {
	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                 time.Now(),
		InterceptionEnabled: true,
		InterceptionRootPEM: testCertPEM(t, "Provider Root CA v2"),
		PerTenantInterceptionRoots: []perTenantInterceptionRoot{
			{Tenant: "tenant_northwind", RootPEM: string(testCertPEM(t, "Northwind Interception Root 2028"))},
		},
		InterceptionPrimaryTenant: "tenant_reference_lab",
	})

	subjectsFor := func(tenant string) []string {
		var out []string
		for _, item := range pkiCertificateItemsForTenant(inv.Items, tenant, nil) {
			if item.Role == "interception_root" {
				out = append(out, item.Subject)
			}
		}
		return out
	}

	nw := subjectsFor("tenant_northwind")
	if len(nw) != 1 || !strings.Contains(nw[0], "Northwind") {
		t.Fatalf("Northwind's interception roots are %v — it must see its own, and only its own", nw)
	}

	// ★ The primary tenant still sees the node-wide root, because its devices genuinely trust that anchor.
	// Without this the fix would blank the screen for the one tenant that was correct before.
	lab := subjectsFor("tenant_reference_lab")
	if len(lab) != 1 || !strings.Contains(lab[0], "Provider Root") {
		t.Fatalf("the primary tenant's interception roots are %v — it must keep the anchor its devices trust", lab)
	}

	// A third tenant, with no root of its own, sees NOTHING here rather than the provider's. Its traffic is
	// refused rather than intercepted, and the setup checklist is where that is said.
	if other := subjectsFor("tenant_acme"); len(other) != 0 {
		t.Fatalf("a tenant with no interception authority was shown %v as its own", other)
	}

	// The operator answering for the deployment sees both — that filter is skipped entirely, and they are who
	// can act on a leftover.
	all := 0
	for _, item := range inv.Items {
		if item.Role == "interception_root" {
			all++
		}
	}
	if all != 2 {
		t.Fatalf("the unfiltered inventory holds %d interception roots, want both", all)
	}
}

// ★ THE CONTROL, and it is not optional here: a deployment with no per-tenant roots at all has ONE root that
// genuinely is everybody's. A rule keyed on "unowned" rather than on "unowned while per-tenant roots exist"
// would blank the interception row on every single-tenant deployment — a much larger blast radius than the
// bug it fixes, and invisible in a test that only ever configures two tenants.
func TestASingleTenantDeploymentStillSeesTheOnlyInterceptionRoot(t *testing.T) {
	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                 time.Now(),
		InterceptionEnabled: true,
		InterceptionRootPEM: testCertPEM(t, "Deployment Root CA"),
	})
	seen := 0
	for _, item := range pkiCertificateItemsForTenant(inv.Items, "tenant_only", nil) {
		if item.Role == "interception_root" {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("a deployment with one shared root showed %d interception roots to its tenant", seen)
	}
}

// ★★ AND ONCE THE PRIMARY HAS ITS OWN ROOT, THE NODE-WIDE ONE BELONGS TO NOBODY (2026-08-19, seen the moment
// tenant_reference_lab was moved onto its own root).
//
// Attributing the node-wide root to the primary organization was right while that organization's devices were
// the ones trusting it. After the move, the certificates page went on naming the provider's root as that
// organization's interception anchor while the trust bundle it actually serves them announces only their own —
// so the screen built to answer "whose authority can read my traffic" was answering with a certificate nobody
// trusts and nothing signs under.
//
// Unowned is the truthful answer, and it is also the operator's cue: a root that belongs to no organization is
// a root that can be retired.
func TestTheNodeWideRootIsUnownedOnceThePrimaryHasItsOwn(t *testing.T) {
	rootsFor := func(t *testing.T, primaryHasOwn bool) (forPrimary []string, unowned int) {
		t.Helper()
		perTenant := []perTenantInterceptionRoot{
			{Tenant: "tenant_northwind", RootPEM: string(testCertPEM(t, "Northwind Interception Root 2028"))},
		}
		if primaryHasOwn {
			perTenant = append(perTenant, perTenantInterceptionRoot{
				Tenant: "tenant_reference_lab", RootPEM: string(testCertPEM(t, "Lab Tenant Interception Root 2028")),
			})
		}
		inv := buildPKICertificateInventory(pkiCertInventoryInput{
			Now:                        time.Now(),
			InterceptionEnabled:        true,
			InterceptionRootPEM:        testCertPEM(t, "Provider Root CA v2"),
			PerTenantInterceptionRoots: perTenant,
			InterceptionPrimaryTenant:  "tenant_reference_lab",
		})
		for _, item := range inv.Items {
			if item.Role != "interception_root" {
				continue
			}
			if item.OwnerUnknown {
				unowned++
			}
			if strings.EqualFold(item.TenantID, "tenant_reference_lab") {
				forPrimary = append(forPrimary, item.Subject)
			}
		}
		return forPrimary, unowned
	}

	// Before: the primary has no root of its own, so the node-wide one is genuinely theirs and must say so.
	forPrimary, unowned := rootsFor(t, false)
	if len(forPrimary) != 1 || !strings.Contains(forPrimary[0], "Provider Root") {
		t.Fatalf("while the primary organization has no root of its own, the node-wide root is theirs and the "+
			"page shows %v", forPrimary)
	}
	if unowned != 0 {
		t.Fatalf("the node-wide root was left unowned while it is still the primary organization's anchor")
	}

	// After: it has its own, so the node-wide root is nobody's.
	forPrimary, unowned = rootsFor(t, true)
	for _, subject := range forPrimary {
		if strings.Contains(subject, "Provider Root") {
			t.Fatalf("the primary organization has its own root and the page still names the provider's root "+
				"as its interception anchor: %v", forPrimary)
		}
	}
	if len(forPrimary) != 1 || !strings.Contains(forPrimary[0], "Lab Tenant") {
		t.Fatalf("the primary organization should see exactly its own root, and sees %v", forPrimary)
	}
	if unowned != 1 {
		t.Fatalf("the node-wide root signs nothing and belongs to nobody, and %d root(s) say so — an operator "+
			"reading this page cannot tell it is retirable", unowned)
	}
}
