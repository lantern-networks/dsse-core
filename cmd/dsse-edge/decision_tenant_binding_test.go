package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"

	"github.com/lantern-networks/dsse-core/model"
)

// reqWithVerifiedChains builds an *http.Request whose TLS state presents the given verified chains, as if it
// arrived over the (T) mTLS transport listener.
func reqWithVerifiedChains(chains [][]*x509.Certificate) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "https://edge/decisions/evaluate", nil)
	if chains != nil {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{chains[0][0]},
			VerifiedChains:   chains,
		}
	}
	return r
}

// tenant isolation (data-plane binding): the decision's tenant must be the one the mTLS CERTIFICATE
// proves (resolved from the issuing Tenant CA), NOT a client-claimed tenant_id in the request body. A body
// that claims a different tenant than its certificate is a cross-tenant attempt and is rejected.
func TestEnrichDecisionRequestWithTransportTenant(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "tenant-A-CA", 21)
	caB := makeTestCA(t, dir, "tenant-B-CA", 22)
	regPath := writeRegistry(t, dir, map[string]string{"tenant_a": caA.pemPath, "tenant_b": caB.pemPath})
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	chainsA := leafSignedBy(t, caA, "dev-a", reg.Pool)
	if chainsA == nil {
		t.Fatal("tenant_a leaf should verify against the pool")
	}

	// labMode=true is passed for the back-compat cases so they exercise the unchanged lab behaviour; the
	// production fail-closed cases pass labMode=false explicitly below.
	const labMode, prodMode = true, false

	t.Run("empty claim is bound to the certificate tenant", func(t *testing.T) {
		req := model.DecisionRequest{} // no client-claimed tenant
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(chainsA), req, reg, labMode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.TenantID != "tenant_a" {
			t.Fatalf("expected authoritative tenant_a binding, got %q", out.TenantID)
		}
	})

	t.Run("matching claim is honored", func(t *testing.T) {
		req := model.DecisionRequest{TenantID: "tenant_a"}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(chainsA), req, reg, labMode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.TenantID != "tenant_a" {
			t.Fatalf("expected tenant_a, got %q", out.TenantID)
		}
	})

	t.Run("cross-tenant claim is denied", func(t *testing.T) {
		// A tenant_a certificate but the body claims tenant_b — the no-mixing invariant: deny, never honor.
		req := model.DecisionRequest{TenantID: "tenant_b"}
		_, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(chainsA), req, reg, labMode)
		if err == nil {
			t.Fatal("ISOLATION VIOLATION: a body claiming tenant_b on a tenant_a certificate must be denied")
		}
	})

	t.Run("plaintext listener (no verified chain) keeps client-supplied tenant", func(t *testing.T) {
		// Back-compat: on the plaintext data plane there is no mTLS chain, so the existing tenant is kept.
		req := model.DecisionRequest{TenantID: "tenant_lab"}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(nil), req, reg, labMode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.TenantID != "tenant_lab" {
			t.Fatalf("plaintext path must keep client tenant, got %q", out.TenantID)
		}
	})

	t.Run("no registry configured is a no-op", func(t *testing.T) {
		req := model.DecisionRequest{TenantID: "tenant_lab"}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(chainsA), req, nil, labMode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.TenantID != "tenant_lab" {
			t.Fatalf("nil registry must keep client tenant, got %q", out.TenantID)
		}
	})

	// Phase 3 (G1, multi-tenant Admin Console//) — production fail-closed on the residual
	// primary-tenant fallback.
	t.Run("production multi-tenant: unresolved tenant (no chain, empty claim) is DENIED", func(t *testing.T) {
		// devMode=false + registry configured + no verified chain + no claimed tenant → the tenant cannot be
		// proven and MUST NOT fall back to the seed tenant downstream: deny.
		req := model.DecisionRequest{} // no claimed tenant
		_, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(nil), req, reg, prodMode)
		if err == nil {
			t.Fatal("FAIL-CLOSED VIOLATION: an unresolved tenant on a multi-tenant production Edge must be denied (no seed fallback)")
		}
	})

	t.Run("production multi-tenant: verified chain still binds authoritatively", func(t *testing.T) {
		// devMode=false but the tenant IS proven by the cert → bound, not denied.
		req := model.DecisionRequest{}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(chainsA), req, reg, prodMode)
		if err != nil {
			t.Fatalf("a cert-proven tenant must bind even in production, got err=%v", err)
		}
		if out.TenantID != "tenant_a" {
			t.Fatalf("expected authoritative tenant_a binding, got %q", out.TenantID)
		}
	})

	t.Run("lab: unresolved tenant (no chain, empty claim) is NOT denied (back-compat seed fallback)", func(t *testing.T) {
		// Identical inputs to the production deny case but labMode=true → keep behaviour: no error, empty
		// tenant kept so the downstream evaluator seed fallback still applies. Lab MUST NOT change.
		req := model.DecisionRequest{}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(nil), req, reg, labMode)
		if err != nil {
			t.Fatalf("lab must not fail-close on an unresolved tenant, got err=%v", err)
		}
		if out.TenantID != "" {
			t.Fatalf("lab should keep the empty tenant (seed fallback applies downstream), got %q", out.TenantID)
		}
	})

	t.Run("production single-tenant (nil registry): unresolved tenant is NOT denied (back-compat)", func(t *testing.T) {
		// Even in production, a single-tenant Edge (no Tenant CA registry) keeps the seed fallback — the
		// fail-closed guard is gated on reg != nil so single-tenant lab/prod is unaffected.
		req := model.DecisionRequest{}
		out, err := enrichDecisionRequestWithTransportTenant(reqWithVerifiedChains(nil), req, nil, prodMode)
		if err != nil {
			t.Fatalf("single-tenant (nil registry) must not fail-close, got err=%v", err)
		}
		if out.TenantID != "" {
			t.Fatalf("single-tenant should keep the empty tenant (seed fallback applies), got %q", out.TenantID)
		}
	})

	// The shared helper is also reused by the lateral-movement-observation ingest (which feeds the
	// tenant-keyed ransomware-anomaly window). Lock its contract directly.
	t.Run("authoritativeTenantForRequest contract", func(t *testing.T) {
		// cert tenant binds an empty claim
		if got, err := authoritativeTenantForRequest(reqWithVerifiedChains(chainsA), "", reg); err != nil || got != "tenant_a" {
			t.Fatalf("empty claim should bind to tenant_a, got %q err=%v", got, err)
		}
		// cross-tenant claim denied
		if _, err := authoritativeTenantForRequest(reqWithVerifiedChains(chainsA), "tenant_b", reg); err == nil {
			t.Fatal("cross-tenant claim must be denied")
		}
		// plaintext keeps (trimmed) claim
		if got, err := authoritativeTenantForRequest(reqWithVerifiedChains(nil), " tenant_lab ", reg); err != nil || got != "tenant_lab" {
			t.Fatalf("plaintext should keep trimmed claim, got %q err=%v", got, err)
		}
	})
}
