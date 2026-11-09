package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ★★★ A STEERED FLOW BELONGS TO THE ORGANIZATION ITS DEVICE'S CERTIFICATE PROVES (2026-08-28, measured by
// putting a second organization on the lab and running one flow as one of its devices).
//
// The mux handler bound the device's IDENTITY from the moment it was written and never its ORGANIZATION: the
// decision request was seeded with this node's own tenant and nothing replaced it. Three things read that
// field — which authority signs the leaf the browser is shown, whose policy is applied, and whose flow the
// record says it was — so for every organization but the operator's, all three were wrong.
//
// Measured on the wire: a device of "Suzuran Foods", holding a certificate from Suzuran's own device CA and
// dialling Suzuran's own transport name, was served a leaf for example.com signed by the DEPLOYMENT's
// interception root while Suzuran's own issuing CA sat loaded on that same Edge.
func TestASteeredFlowIsKeyedToTheOrganizationTheCertificateProves(t *testing.T) {
	_, registry, _, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Suzuran Device CA")
	if _, err := registry.Register("tenant_suzuran", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}

	withChain := httptest.NewRequest(http.MethodGet, "/", nil)
	withChain.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{caCert}}}

	if got := steerMuxFlowTenant(withChain, registry, "tenant_operator", "suzuran-walk-1"); got != "tenant_suzuran" {
		t.Fatalf("the flow was keyed to %q — the leaf its browser is shown would be signed by the wrong "+
			"authority, its own organization's policy would not apply, and the record would name somebody "+
			"else", got)
	}

	// ★ AN UNRESOLVED CHAIN KEEPS TODAY'S ANSWER. The /steer path denies this on a multi-tenant production
	// Edge; turning that on here in the same change would convert an attribution defect into an outage for
	// every device whose CA is not registered. It is the remaining half, and it is no longer silent.
	stranger, _ := tenantCATestCA(t, "Unregistered CA")
	unknown := httptest.NewRequest(http.MethodGet, "/", nil)
	unknown.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{stranger}}}
	if got := steerMuxFlowTenant(unknown, registry, "tenant_operator", "stranger-1"); got != "tenant_operator" {
		t.Fatalf("an unresolved chain changed behaviour: %q", got)
	}

	// No registry at all is a single-tenant Edge, and it is left exactly as it was.
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := steerMuxFlowTenant(plain, nil, "tenant_operator", "no-tls"); got != "tenant_operator" {
		t.Fatalf("a single-tenant Edge changed behaviour: %q", got)
	}
}

// The OS and posture a device reports on its steer-mux CONNECT are kept under the organization its
// certificate proves, beside what its periodic report says (2026-11-06: an unknown OS on a customer's Devices
// screen, because the CONNECT wrote under this node's organization and the two writers replaced each other).
func TestAConnectRecordsTheDevicesOSUnderItsOwnOrganization(t *testing.T) {
	_, registry, _, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Acceptance B Device CA")
	if _, err := registry.Register("tenant_customer", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}
	store := newEndpointRuntimeStore()
	now := time.Now()
	yes := true
	store.ingestFromReport("win-1", "tenant_customer", "", &yes, &yes, "windows_collector", "198.51.100.7", now)

	r := httptest.NewRequest(http.MethodConnect, "/steer-mux", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{caCert}}}
	r.Header.Set(deviceHeaderOS, "Windows 10 Pro 22H2")
	ingestSteerMuxConnect(store, r, registry, "tenant_operator", "win-1", now.Add(time.Second))

	store.mu.RLock()
	e := store.m["win-1"]
	store.mu.RUnlock()
	if e == nil || e.tenant != "tenant_customer" {
		t.Fatalf("the CONNECT moved the device's runtime entry to another organization: %+v", e)
	}
	view := e.runtimeView(now.Add(2 * time.Second))
	if view.OS != "Windows 10 Pro 22H2" {
		t.Errorf("the OS from the CONNECT is not on the device's own entry: %q", view.OS)
	}
	if view.Posture.DiskEncryptionEnabled == nil {
		t.Error("the CONNECT erased the posture the periodic report had recorded")
	}
}

func TestTheSteerMuxHandlerRecordsTheConnectThroughTheOrganizationHelper(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "ingestSteerMuxConnect(deviceRuntime, r, tcaReg, runtimeEvaluator.PolicyBundle.TenantID, transportDeviceID, time.Now())") {
		t.Fatal("the steer-mux CONNECT no longer records through ingestSteerMuxConnect")
	}
	if strings.Contains(string(src), "deviceRuntime.ingestFromConnect(transportDeviceID, runtimeEvaluator.PolicyBundle.TenantID") {
		t.Fatal("the CONNECT is recorded under this node's organization again")
	}
}
