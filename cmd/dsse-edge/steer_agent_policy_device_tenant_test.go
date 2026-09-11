package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/steerexclusion"
)

// asVerifiedDevice calls a /steer route the way an endpoint agent does: a verified client certificate and no
// admin session at all.
func asVerifiedDevice(t *testing.T, handler http.Handler, identity, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: identity}}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// ★ A SECOND ORGANIZATION'S DEVICE WAS SERVED THE FIRST ORGANIZATION'S ENFORCEMENT (2026-08-16). Five /steer
// routes resolved the tenant as `evaluator.PolicyBundle.TenantID` — the tenant of the NODE — rather than the
// tenant of the DEVICE that authenticated: agent-policy (which apps bypass steering), agent-tuning,
// server-initiated-export (inbound firewall exceptions), the agent report, and region-endpoints (allowed and
// home regions, i.e. residency).
//
// On a single-tenant Edge those two values are the same string and nothing is visible. This product now ships
// an Edge that admits several organizations, and there the device of one customer was handed another
// customer's rules — and filed its own reports under the wrong organization, which is where the anchor
// adoption measurement reads from.
//
// The exclusion set is the one tested here because it is the sharpest: it decides which applications BYPASS
// steering, so receiving the wrong organization's set is a device inspecting, or not inspecting, according to
// somebody else's policy.
func TestADevicesSteerPolicyIsItsOwnOrganizationsNotTheNodes(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("nw-laptop-1", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("lab-laptop-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// Each organization's own tenant-wide set. The node's tenant is tenant_lab_001 (testEvaluator).
	exclusions := steerexclusion.NewStore()
	for tenant, app := range map[string]string{
		"tenant_lab_001":   "com.acme.labonly",
		"tenant_northwind": "com.northwind.ownapp",
	} {
		if _, err := exclusions.Upsert(steerexclusion.Policy{
			TenantID: tenant, ScopeType: "tenant", ExcludedAppSigningIDs: []string{app}, Status: "active",
		}, time.Now()); err != nil {
			t.Fatalf("seed %s: %v", tenant, err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		EnrolledLedger:  ledger,
		SteerExclusions: exclusions,
		AdminAuth:       newAdminAuthStore(),
	})

	nw := asVerifiedDevice(t, handler, "nw-laptop-1", "/steer/agent-policy").Body.String()
	lab := asVerifiedDevice(t, handler, "lab-laptop-1", "/steer/agent-policy").Body.String()

	if strings.Contains(nw, "com.acme.labonly") {
		t.Fatalf("northwind's device was served tenant_lab_001's steer exclusions: %s", nw)
	}
	// Both halves: its own set is present in the same answer, or this passes on an empty policy — which is
	// what a device that received nothing looks like from here.
	if !strings.Contains(nw, "com.northwind.ownapp") {
		t.Fatalf("northwind's device did not receive its OWN exclusions: %s", nw)
	}
	if !strings.Contains(lab, "com.acme.labonly") {
		t.Fatalf("the node's own tenant lost its exclusions: %s", lab)
	}
	if strings.Contains(lab, "com.northwind.ownapp") {
		t.Fatalf("the lab device was served northwind's exclusions: %s", lab)
	}
}

// ★ THE DOCUMENT MUST STATE THE ORGANIZATION, because the DEVICE cannot work it out (2026-09-04, measured on
// a real Mac). The issuing CA is not on the device's disk and not in any keychain, and the profile carries
// only its SHA-256 — so a device handed a new organization's profile went on presenting the old
// organization's certificate, which handshakes perfectly within one deployment. This field is how the agent
// finds out, and it is signed, so it cannot be chosen by anyone on the network.
func TestTheSteerPolicyDocumentStatesTheDevicesOrganization(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("nw-laptop-1", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		EnrolledLedger: ledger,
		AdminAuth:      newAdminAuthStore(),
	})
	raw := asVerifiedDevice(t, handler, "nw-laptop-1", "/steer/agent-policy").Body.Bytes()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("the steering document is not JSON: %v", err)
	}
	tid, _ := body["tenant_id"].(string)
	if strings.TrimSpace(tid) != "tenant_northwind" {
		t.Fatalf("the document must name the organization the DEVICE belongs to (tenant_northwind), got %#v — "+
			"this field is the only way an agent can learn it, because the issuing CA is on neither the "+
			"device's disk nor in any of its keychains", body["tenant_id"])
	}
}
