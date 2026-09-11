package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	swg "github.com/lantern-networks/dsse-core/swg"
)

// GAP-1 end-to-end integration: prove the decrypt-all egress FORWARD path runs WITHOUT -lab-mode.
//
// This exercises the same full path the in-process NE/WFP forward takes — connector gate, policy decision,
// tenant-restriction header rewrite, readiness precondition, upstream proxy — but with LabMode:false. The
// trusted device path forwards (302 + injected tenant header); the external route, same request without
// connector credentials, is still rejected (401). Together these show decrypt-all egress works in production
// (no lab-mode relaxation) AND the external endpoint stays gated.
//
// The readiness precondition is satisfied here via RuntimeTLSDecryptionObserved (the operator/runtime asserts
// decrypt-all is configured + executing) — the production-correct way to clear the fail-closed "don't egress
// in the clear until decryption is observed" gate; it is NOT relaxed by removing lab-mode.
func TestSWGHTTPEgressForwardsDecryptAllWithoutLabMode(t *testing.T) {
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	operatorConfigPath := t.TempDir() + "/operator_config.json"
	if err := os.WriteFile(operatorConfigPath, []byte(`{
  "schema_version": "swg_tenant_restriction_operator_config.v1",
  "status": "active",
  "tenant_id": "tenant_swg_lab",
  "header_values": [
    {
      "ref": "operator_config_ref:google_workspace_allowed_domains",
      "tenant_id": "tenant_swg_lab",
      "saas_application_id": "saas_google_workspace",
      "provider": "google_workspace",
      "header_name": "X-GoogApps-Allowed-Domains",
      "header_value_kind": "configured_allowed_domains",
      "value": "allowed.example",
      "status": "active",
      "metadata": {
        "operator_managed": true,
        "operator_config_value_secret": false,
        "captured_secret_material_committed": false,
        "report_value_material_logged": false
      }
    }
  ],
  "metadata": { "designated_operator_config_file": true }
}`), 0600); err != nil {
		t.Fatalf("write operator config: %v", err)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true, // production readiness: decrypt-all is configured + observed
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	baseConfig := func() edgeSWGHTTPEgressHandlerConfig {
		return edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				Policies:      policies,
				PolicyBundle:  bundle,
				EdgeRegionID:  "local",
				EdgeClusterID: "local-edge-001",
			},
			Writer:           writer,
			Registry:         connector.NewRegistry(),
			ProxyClient:      &http.Client{Transport: &redirectRecordingHTTPRoundTripper{redirectBody: &readTrackingReadCloser{}}},
			SWGRuntime:       swgRuntime,
			DecisionStore:    newAccessDecisionStore(),
			InspectionEvents: newInspectionEventStore(),
			LabMode:          false, // PRODUCTION
		}
	}

	// Trusted in-process NE/WFP path (DeviceAuthenticatedInProcess) — must forward without -lab-mode.
	deviceCfg := baseConfig()
	deviceCfg.DeviceAuthenticatedInProcess = true
	device := newEdgeSWGHTTPEgressHandler(deviceCfg)
	reqDev := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	reqDev.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
	recDev := httptest.NewRecorder()
	device.ServeHTTP(recDev, reqDev)
	if recDev.Code != http.StatusFound {
		t.Fatalf("non-lab device decrypt-all egress: status = %d, want 302 (forwarded); body=%s", recDev.Code, recDev.Body.String())
	}
	if got := recDev.Header().Get("Location"); got != "https://accounts.google.com/signin/v2/identifier" {
		t.Fatalf("Location = %q, want the upstream redirect (proves the request reached the origin proxy)", got)
	}

	// External /swg/http-egress route, SAME request, no connector credentials — still rejected in production.
	external := newEdgeSWGHTTPEgressHandler(baseConfig())
	reqExt := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	reqExt.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
	recExt := httptest.NewRecorder()
	external.ServeHTTP(recExt, reqExt)
	if recExt.Code != http.StatusUnauthorized {
		t.Fatalf("external route w/o connector creds: status = %d, want 401 (must stay gated in production)", recExt.Code)
	}
}
