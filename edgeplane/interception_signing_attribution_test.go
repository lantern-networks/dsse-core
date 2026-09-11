package edgeplane

import (
	"strings"
	"testing"
	"time"
)

// ★★ AN UNATTRIBUTED FLOW IS SIGNED UNDER A NAMED CUSTOMER'S AUTHORITY, AND NOTHING SAID SO (2026-08-18).
//
// issuerFor refuses to sign for an organization that has no issuer of its own — that boundary is tested next
// door and it holds. What it does NOT refuse is a flow whose organization did not resolve at all: the empty
// tenant falls through to the node-wide intermediate, which belongs to ONE named organization. The comment at
// that line reasons that the device's trust store refuses the result anyway. That is true of every device
// except the primary organization's own, which trusts that anchor and accepts the certificate silently — so
// the single case where it matters is the case where it works.
//
// The counter is the deliverable here, not the refusal: taking interception away from unattributed traffic is
// a decision that needs a number first, and before this there was no way to obtain one. `issuerScope` already
// carried the answer per flow and was thrown into a cache key.
func TestSigningAuthorityIsCountedIncludingTheUnattributedFallback(t *testing.T) {
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

	before := InterceptionSigningCounts()

	// 1. An organization with its own offline root. Distinct host per call: the leaf cache would otherwise
	// serve the second request without ever reaching issuerFor, and the counter would measure the cache.
	if _, err := leafIssuerCN(t, interception, "tenant_northwind", "own.example.com"); err != nil {
		t.Fatalf("northwind: %v", err)
	}
	// 2. The primary organization, signed by the anchor that is genuinely its own.
	if _, err := leafIssuerCN(t, interception, "tenant_lab", "primary.example.com"); err != nil {
		t.Fatalf("primary: %v", err)
	}
	// 3. ★ The flow whose organization did not resolve is REFUSED, not signed under the primary's authority.
	// Closed on 2026-08-18 after the counter measured it at 0 on the reference lab across 33 signatures.
	if _, err := leafIssuerCN(t, interception, "", "unattributed.example.com"); err == nil {
		t.Fatal("a flow whose organization did not resolve was signed under a named organization's CA — whose " +
			"own devices accept that certificate without complaint, so nothing looks wrong")
	} else if !strings.Contains(err.Error(), "tenant_lab") {
		t.Fatalf("the refusal does not name whose authority was declined: %v", err)
	}
	// 4. ★ An organization that has not been given its own authority is inspected under THIS DEPLOYMENT's root
	// — counted as its own class, because "how much traffic is inspected under the deployment's CA rather than
	// the customer's" is the number the per-organization PKI work is driving to zero. Corrected 2026-08-28: it
	// used to be refused, which took inspection away from every organization but one the moment a second
	// organization brought its own root, and said nothing anywhere.
	unprovisioned, err := leafIssuerCN(t, interception, "tenant_unprovisioned", "fallback.example.com")
	if err != nil {
		t.Fatalf("an organization with no authority of its own lost interception entirely: %v", err)
	}
	if strings.Contains(unprovisioned, "Northwind") {
		t.Fatalf("it was signed under another customer's CA: %q", unprovisioned)
	}

	after := InterceptionSigningCounts()
	for _, want := range []struct {
		class string
		delta uint64
	}{
		{"own_offline_root", 1},
		{"primary_own", 1},
		{"refused_unattributed", 1},
		{"deployment_root_no_own_authority", 1},
	} {
		if got := after[want.class] - before[want.class]; got != want.delta {
			t.Fatalf("class %q moved by %d, want %d — the signing authority is not being recorded, so "+
				"'we sign nothing under a customer's CA' and 'we sign a great deal' remain the same screen",
				want.class, got, want.delta)
		}
	}

	// ★ THE CONTROL. Without it this test passes for an implementation that increments
	// unattributed_under_primary on every call, which would make the number useless in exactly the direction
	// that matters — it would always look like there is a problem, so nobody would act on it.
	mid := InterceptionSigningCounts()
	for _, host := range []string{"c1.example.com", "c2.example.com", "c3.example.com"} {
		if _, err := leafIssuerCN(t, interception, "tenant_northwind", host); err != nil {
			t.Fatalf("control %s: %v", host, err)
		}
	}
	end := InterceptionSigningCounts()
	if moved := end["refused_unattributed"] - mid["refused_unattributed"]; moved != 0 {
		t.Fatalf("three attributed flows moved the unattributed counter by %d", moved)
	}
	if moved := end["own_offline_root"] - mid["own_offline_root"]; moved != 3 {
		t.Fatalf("three flows under the organization's own root counted as %d", moved)
	}
}

// ★★★ THE MODE THE INSTALLER GENERATES WAS NOT COUNTED (2026-08-26, measured on the release lab). countSigning
// was reached only when per-tenant offline issuers were loaded. A generated deployment signs leaves with its
// own interception root directly, so /admin/interception-intermediate answered
// `signing_counts_since_start: {}` for ever — while the Edge was minting leaves under that very authority. A
// flow to example.com came back signed by "DSSE Deployment Interception CA" and the number stayed zero.
//
// The zero is the damage: it is the number an operator reads to answer "is this deployment inspecting", and
// it said no.
func TestTheDirectRootModeCountsWhatItSigns(t *testing.T) {
	now := time.Now().UTC()
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}

	before := InterceptionSigningCounts()["direct_root"]
	// Distinct hosts: the leaf cache would otherwise serve the second without reaching issuerFor, and the
	// counter would be measuring the cache rather than the signing.
	for _, host := range []string{"one.example.com", "two.example.com"} {
		if _, lerr := leafIssuerCN(t, interception, "tenant_lab", host); lerr != nil {
			t.Fatalf("%s: %v", host, lerr)
		}
	}
	after := InterceptionSigningCounts()["direct_root"]
	if after-before != 2 {
		t.Fatalf("two leaves were signed by the deployment's own root and the counter moved by %d — this is the "+
			"number an operator reads to decide whether the deployment inspects", after-before)
	}
}
