package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
)

// GAP-1: the macOS NE / Windows WFP decrypt-all egress is served IN PROCESS by the SWG egress handler after
// the edge intercepts a steered flow. That handler is also the EXTERNAL /swg/http-egress route, which requires
// connector authorization. Before this change the only way to let the (non-connector) NE forward through was
// -lab-mode, which also relaxed every other production guard. The fix splits the two callers: the trusted
// in-process path (DeviceAuthenticatedInProcess) skips connector auth because the flow was already
// device-authenticated at the (T) transport mTLS layer; the external route keeps the connector gate.
//
// This test pins BOTH halves of that contract in PRODUCTION (LabMode:false):
//   - external route without connector credentials  -> 401 (gate still applies; not bypassable)
//   - trusted in-process device path                -> NOT 401 (gate skipped; runs without -lab-mode)
//
// The auth skip is structurally unforgeable (it is a config flag set only on the SetHTTPHandler handler, never
// on the external mux route — there is no request header a caller can set to reach it).
func TestSWGHTTPEgressConnectorGateSkippedOnlyForDeviceInProcessPath(t *testing.T) {
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	base := edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{
			Policies:      policies,
			PolicyBundle:  bundle,
			EdgeRegionID:  "local",
			EdgeClusterID: "local-edge-001",
		},
		Registry: connector.NewRegistry(),
		LabMode:  false, // PRODUCTION: the connector gate is live (no lab-mode relaxation)
	}

	// External /swg/http-egress route, no connector credentials -> connector authorization rejects it.
	external := newEdgeSWGHTTPEgressHandler(base)
	recExt := httptest.NewRecorder()
	external.ServeHTTP(recExt, httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil))
	if recExt.Code != http.StatusUnauthorized {
		t.Fatalf("external route without connector creds: status = %d, want 401 (connector gate must apply in "+
			"production and must not be bypassable); body=%s", recExt.Code, recExt.Body.String())
	}

	// Trusted in-process NE/WFP decrypt-all forward: same request, but it must SKIP the connector gate. It then
	// gets past auth and fails on the missing target URL (400) instead of 401 — proving the gate was skipped.
	deviceCfg := base
	deviceCfg.DeviceAuthenticatedInProcess = true
	device := newEdgeSWGHTTPEgressHandler(deviceCfg)
	recDev := httptest.NewRecorder()
	device.ServeHTTP(recDev, httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil))
	if recDev.Code == http.StatusUnauthorized {
		t.Fatalf("device in-process path returned 401 — it MUST skip the connector gate (the device is " +
			"transport-mTLS authenticated, not a connector). This is the GAP-1 fix; without it decrypt-all egress " +
			"needs -lab-mode.")
	}
	if recDev.Code != http.StatusBadRequest {
		t.Fatalf("device in-process path: status = %d, want 400 (past the connector gate, then fails on the "+
			"missing target URL); body=%s", recDev.Code, recDev.Body.String())
	}
}
