package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ Invalidate() HAD NO CALLER (2026-08-29, found by a Windows machine adopting a bundle that named the
// DEPLOYMENT's transport authority for an organization that has its own).
//
// The builder caches one signed bundle per organization and re-signs only when its generation moves. The
// generation moved when the SHARED anchor set changed — and never when an organization's OWN certificate
// arrived. So an Edge handed an organization's material after it had already answered that organization once
// went on serving the old bundle, naming only the shared anchor, until the process restarted.
//
// The device then cannot verify the door its own profile tells it to dial: every (T) call fails and the
// ledger reads green throughout. Restarting the Edge "fixed" it, which is the worst kind of fix — it makes a
// permanent defect look like a transient.
//
// This reads the source because the failure is an ABSENT CALL, and no unit test of the builder can see one.
// The same shape as the mint report reading the wrong moment: the helper was right and nothing invoked it.
func TestTheBundleIsReSignedWhenAnOrganizationsMaterialArrives(t *testing.T) {
	body, err := os.ReadFile("transport_tenant_certificates.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)

	// Every path that changes what this node serves for an organization must say so to the builder.
	for _, path := range []struct{ after, why string }{
		{"transportTenantCertificates.put(tenant, leaf.DNSNames, &pair, anchor, fromDisk)\n\t\tinvalidateTrustBundles",
			"material loaded from disk"},
		{"transportTenantCertificates.putPendingUnlessServingSuccessor(tenant, leaf.DNSNames, &pair, anchor, mat.SuccessorAnchorSHA256, effective) {\n\t\t\treturn nil\n\t\t}\n\t\t// An announcement",
			"a new authority announced alongside the one in force"},
		{"transportTenantCertificates.put(tenant, leaf.DNSNames, &pair, anchor, effective)\n\tinvalidateTrustBundles",
			"material installed from the control plane"},
	} {
		if !strings.Contains(source, path.after) {
			t.Errorf("%s does not invalidate the cached bundles — that organization's devices keep being "+
				"handed the anchors this node held BEFORE, until it restarts", path.why)
		}
	}

	// And the builder still HAS the method: a test that only greps call sites passes when the thing called
	// has been deleted.
	builder, err := os.ReadFile("trust_bundle_per_tenant.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(builder), "func (b *perTenantTrustBundles) Invalidate()") {
		t.Error("the builder no longer offers Invalidate, so the calls above name something that is gone")
	}
}
