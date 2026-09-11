package edgeplane

import (
	"strings"
	"testing"
	"time"
)

// ★ The screen must not tell an operator that the work they just finished has not happened. The scope note
// named the node's own organization as still on the node-wide intermediate whenever a primary tenant was
// configured — unconditionally, including after that organization had been given a root of its own.
//
// Both directions are held here, because the sentence is only useful if it can say either thing.
func TestTheScopeNoteSaysWhetherTheNodesOwnOrganizationStillUsesTheSharedIntermediate(t *testing.T) {
	lab := interceptionWithTenantIssuers(t, "tenant_reference_lab", "tenant_northwind")
	lab.SetOfflinePrimaryTenant("tenant_reference_lab")

	note := lab.InterceptionRootScope().Note
	if strings.Contains(note, "keeps the node-wide intermediate") {
		t.Fatalf("the node's own organization has its own root and the note still says it does not: %q", note)
	}
	if !strings.Contains(note, "signs nothing and can be retired") {
		t.Fatalf("every organization signs under its own root and the note does not say the node-wide "+
			"intermediate is now unused, which is the fact an operator would act on: %q", note)
	}

	// The control: while the node's own organization is still on the shared intermediate, the note must say
	// so by name. Losing this half would hide the state the whole per-tenant PKI effort exists to leave.
	partial := interceptionWithTenantIssuers(t, "tenant_northwind")
	partial.SetOfflinePrimaryTenant("tenant_reference_lab")
	note = partial.InterceptionRootScope().Note
	if !strings.Contains(note, "keeps the node-wide intermediate") ||
		!strings.Contains(note, "tenant_reference_lab") {
		t.Fatalf("the node's own organization is still on the shared intermediate and the note does not say "+
			"so by name: %q", note)
	}
	if strings.Contains(note, "signs nothing and can be retired") {
		t.Fatalf("the note claims the node-wide intermediate is unused while an organization still uses it: %q", note)
	}
}

// interceptionWithTenantIssuers builds an interception engine holding a real offline issuer for each named
// organization, using the same bundle helper the per-tenant signing tests use.
func interceptionWithTenantIssuers(t *testing.T, tenants ...string) *NetworkExtensionLabTLSInterception {
	t.Helper()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	for _, tenant := range tenants {
		rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, tenant, now)
		if _, err := interception.LoadOfflineTenantIntermediate(tenant, rootPEM, interPEM, keyPEM); err != nil {
			t.Fatalf("load %s: %v", tenant, err)
		}
	}
	return interception
}
