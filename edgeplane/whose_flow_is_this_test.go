package edgeplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ MEASURED ON A REAL MAC, 2026-08-29. A device enrolled into a customer organization — by THIS Edge,
// which logged `enroll_issued tenant="tenant_j32kx…"` for it — steered every flow and had every one refused:
//
//	handleNewFlow decision=accepted provider_decision_action=tunnel        (26 flows)
//	handleNewFlow edge_round_trip_error_category=tenant_scope_mismatch     (26 flows)
//	curl https://example.com -> 000
//
// The guard compared the device's tenant to config.TenantID: one value, read once at startup from the policy
// bundle this Edge process loaded — the NODE's own organization, `tenant_default` on that deployment. So
// inspection worked for exactly one organization per node, and every other customer's devices were
// fail-closed by accident: no browsing, no explanation, nothing wrong with their configuration.
func roundTripBody(t *testing.T, tenant string) *strings.Reader {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schema_version":       networkExtensionRuntimeCopyRoundTripRequestSchema,
		"tenant_id":            tenant,
		"request_id":           "req-1",
		"destination_host":     "example.test",
		"destination_port":     443,
		"upstream_payload_b64": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(body))
}

func categoryOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Category string `json:"category"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Category
}

func TestACustomersDeviceIsNotRefusedByTheNodesOwnTenant(t *testing.T) {
	handler := NewNetworkExtensionRuntimeCopyRoundTripHandler(NetworkExtensionRuntimeCopyRoundTripHandlerConfig{
		TenantID: "tenant_default", // the node's own organization
		DeviceTenant: func(r *http.Request) (string, bool) {
			return "tenant_j32kxkri2wajxrllj2kiqmfghe", true // what the device's certificate says
		},
		TransportIdentity: func(r *http.Request) (string, bool) { return "shinnomac-mini", true },
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, NetworkExtensionRuntimeCopyRoundTripPath,
		roundTripBody(t, "tenant_j32kxkri2wajxrllj2kiqmfghe")))
	if got := categoryOf(t, rec); got == "tenant_scope_mismatch" {
		t.Fatalf("a device enrolled into a customer organization was refused because the NODE belongs to "+
			"another one — every steered flow dies and the machine has no network (status %d)", rec.Code)
	}
}

// A device claiming a tenant its certificate does not say is still refused. The resolver moved the authority
// from the node's config file to the certificate; it did not remove the check.
func TestADeviceClaimingSomebodyElsesTenantIsStillRefused(t *testing.T) {
	handler := NewNetworkExtensionRuntimeCopyRoundTripHandler(NetworkExtensionRuntimeCopyRoundTripHandlerConfig{
		TenantID: "tenant_default",
		DeviceTenant: func(r *http.Request) (string, bool) {
			return "tenant_j32kxkri2wajxrllj2kiqmfghe", true
		},
		TransportIdentity: func(r *http.Request) (string, bool) { return "shinnomac-mini", true },
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, NetworkExtensionRuntimeCopyRoundTripPath,
		roundTripBody(t, "tenant_c2nehht46mrrpyp6fx75oz7n7e")))
	if got := categoryOf(t, rec); got != "tenant_scope_mismatch" {
		t.Fatalf("a device asked to act as another organization and was not refused: category=%q status=%d",
			got, rec.Code)
	}
}

// With no resolver — a single-tenant deployment, and every caller before today — the node's tenant governs
// exactly as it did.
func TestWithNoResolverTheNodesTenantStillGoverns(t *testing.T) {
	handler := NewNetworkExtensionRuntimeCopyRoundTripHandler(NetworkExtensionRuntimeCopyRoundTripHandlerConfig{
		TenantID:          "tenant_default",
		TransportIdentity: func(r *http.Request) (string, bool) { return "shinnomac-mini", true },
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, NetworkExtensionRuntimeCopyRoundTripPath,
		roundTripBody(t, "tenant_somebody_else")))
	if got := categoryOf(t, rec); got != "tenant_scope_mismatch" {
		t.Fatalf("a single-tenant deployment stopped scoping its data path: category=%q", got)
	}
}
