package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

func installBundleAs(t *testing.T, handler http.Handler, bearer, tenant string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenant-install-bundle/"+tenant, nil)
	req.Header.Set("authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// ★ WHAT AN INSTALLER EMBEDS, IN ONE ANSWER (2026-08-16). An agent's trusted authorities are fixed when it is
// installed, so the material has to be readable as a single consistent set. Three separate downloads is how a
// package ends up pinning one organization's transport anchor beside another organization's interception
// root — and nothing downstream would notice, because each piece is individually valid.
//
// The organization's OWN interception root is the part that matters here: it is what its endpoints must hold
// for their traffic to be inspected at all, and once each organization signs under its own CA, embedding the
// deployment's shared anchor instead would pin the operator's root into a customer's fleet.
func TestTheInstallBundleCarriesThisOrganizationsOwnAuthorities(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	code, body := installBundleAs(t, handler, testTenantCANorthwindBearer, "tenant_northwind")

	if code != http.StatusOK {
		t.Fatalf("a tenant admin could not read its OWN install material: HTTP %d %v", code, body)
	}
	if body["tenant_id"] != "tenant_northwind" {
		t.Fatalf("install material for %v", body["tenant_id"])
	}
	// This deployment has no interception configured at all in this harness, so the honest answer is
	// incomplete — and it must SAY so rather than emit an empty string an installer would embed.
	if body["complete"] != false {
		t.Fatalf("complete=%v with no interception material; an installer would ship an agent that trusts nothing", body["complete"])
	}
}

// And it stops at the organization's own boundary, like every other tenant PKI act.
func TestTheInstallBundleOfAnotherOrganizationIsRefused(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)

	code, body := installBundleAs(t, handler, testTenantCANorthwindBearer, "tenant_acme")

	if code != http.StatusForbidden {
		t.Fatalf("reading another organization's install material returned HTTP %d %v", code, body)
	}
}

// ★ AND IT NAMES THE ORGANIZATION'S OWN INTERCEPTION ROOT WHEN IT HAS ONE — flagged as its own, because the
// same field carries the deployment's shared anchor for an organization that has not been onboarded yet, and
// an installer that could not tell the two apart would pin the operator's root into a customer's fleet.
func TestTheInstallBundleFlagsWhoseInterceptionRootItIs(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	handler := newServerWithConfig(serverConfig{
		Evaluator:              testEvaluator(),
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      testAgentPolicySigner(t),
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      5,
		AdminAuth:              newAdminAuthStore(),
		// The organization that operates this deployment — see operator_is_an_organization_not_a_role.go.
		// Without it the caller below holds super_admin in a CUSTOMER organization, which is no longer enough.
		OperatorTenantID: "tenant_lab_001",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant-install-bundle/tenant_northwind", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body["interception_root_is_own"] != true {
		t.Fatalf("the organization's own root was not flagged as its own: %v", body["interception_root_is_own"])
	}
	if !strings.Contains(body["interception_root_common_name"].(string), "Northwind") {
		t.Fatalf("the embedded root is %v — not this organization's", body["interception_root_common_name"])
	}
	if body["complete"] != true {
		t.Fatalf("complete=%v with both halves present", body["complete"])
	}
	// The signed bundle travels with it, so the agent's first serial comes from the installer rather than
	// from its first network fetch — which is the point of fixing this at install time.
	if body["trust_bundle"] == nil {
		t.Fatal("no signed trust bundle to embed: the agent's first serial would come from the network")
	}
}

// ★ AFTER A REVOCATION THE FALLBACK IS THE DEFECT (2026-08-16, found live on the reference lab). An
// organization with no issuer of its own falls back to the node's anchor, because that is genuinely what
// signs its traffic. A REVOKED organization has no issuer for the opposite reason: this node decided its
// traffic must not be signed under any other authority. Falling back there handed its installer the
// deployment's root and called the bundle complete — the same shape as the signing defect where an emptied
// per-tenant set read as "per-tenant signing is not in force", now wearing the distribution path's clothes.
//
// A device built from that bundle would pin a root that will never appear in its traffic, and would trust the
// very authority the revocation removed it from.
func TestARevokedOrganizationGetsNoInterceptionRootToEmbed(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	handler := newServerWithConfig(serverConfig{
		Evaluator:              testEvaluator(),
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      testAgentPolicySigner(t),
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      5,
		AdminAuth:              newAdminAuthStore(),
		// The organization that operates this deployment — see operator_is_an_organization_not_a_role.go.
		// Without it the caller below holds super_admin in a CUSTOMER organization, which is no longer enough.
		OperatorTenantID: "tenant_lab_001",
	})
	read := func() map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenant-install-bundle/tenant_northwind", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body
	}

	// The positive control, in the same test: before the revocation this bundle IS buildable, and carries
	// this organization's own root. Without it, "no root to embed" proves nothing — a broken route answers
	// the same way.
	before := read()
	if before["complete"] != true || before["interception_root_is_own"] != true {
		t.Fatalf("the control failed: a healthy organization's bundle was not complete and its own: %v", before)
	}

	if _, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "key custody lost"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	after := read()
	if after["interception_revoked"] != true {
		t.Fatalf("the bundle did not say the authority was revoked: %v", after)
	}
	if reason, _ := after["interception_revoked_reason"].(string); !strings.Contains(reason, "custody") {
		t.Fatalf("the reason is not carried to whoever must decide what to load instead: %q", reason)
	}
	if pem, _ := after["interception_root_pem"].(string); strings.TrimSpace(pem) != "" {
		t.Fatalf("a revoked organization was handed a root to embed:\n%s", pem)
	}
	if after["complete"] != false {
		t.Fatalf("an installer would have been built for a revoked organization: complete=%v", after["complete"])
	}
}
