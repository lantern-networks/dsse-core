package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ THE NODE'S OWN ORGANIZATION IS NOT A THIRD ANSWER (2026-09-05, after a day whose every device-side
// defect came from a device sitting in the wrong organization).
//
// steerDeviceTenant asks two questions that can be answered with authority — which registered Tenant CA the
// certificate chains to, and which organization the control plane enrolled the device into — and used to
// return the NODE's tenant when neither answered. The comment at the call site already said why that is
// wrong, one line above the line that did it:
//
//	"Handing an organization the material of whichever organization happens to own the Edge is how a
//	 second customer received the first one's enforcement."
//
// On a deployment made by dsse-install the node's tenant is tenant_default, which is the OPERATOR's
// organization — so an unattributable device was served the enforcement configuration of the organization
// that administers all the others.
func TestADeviceThisDeploymentCannotPlaceIsRefusedRatherThanServedTheNodesOwn(t *testing.T) {
	// No Tenant CA registry and no enrolled inventory: neither question can be answered.
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	rec := asVerifiedDevice(t, handler, "a-device-nobody-enrolled", "/steer/agent-policy")
	if rec.Code == http.StatusOK {
		t.Fatalf("an unattributable device was served a steering document: %s", rec.Body.String())
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cannot say which organization") {
		t.Fatalf("the refusal must say what could not be established, got: %s", body)
	}
	// And it must not name the node's organization as if it were the answer.
	if strings.Contains(body, `"tenant_id":"tenant_lab_001"`) {
		t.Fatalf("the refusal handed over the node's own organization anyway: %s", body)
	}
}

var _ = httptest.NewRecorder
