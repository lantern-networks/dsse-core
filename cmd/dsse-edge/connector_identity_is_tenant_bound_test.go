package main

import (
	"crypto/tls"
	"time"

	"crypto/x509"
	connector "github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"
)

func connectorRequestPresenting(chains [][]*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/connectors/conn_lab_001/effective-routes", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{chains[0][0]},
		VerifiedChains:   chains,
	}
	return r
}

// ★ A CONNECTOR BELONGS TO EXACTLY ONE ORGANIZATION (operator, 2026-08-19), and that is what makes this a
// cross-tenant question rather than a naming one. An Edge serves SEVERAL organizations, so its device-trust
// set holds several organizations' CAs — and the binding check compared only the certificate's COMMON NAME to
// the connector id. Any organization whose CA this Edge accepts could therefore mint a certificate naming
// another organization's connector, and it would be bound to it.
//
// The tenant is taken from the ISSUING CA, never from anything the caller says, which is the same rule the
// transport already uses to key a flow to its organization.
func TestAConnectorCertificateMustComeFromItsOwnOrganizationsCA(t *testing.T) {
	dir := t.TempDir()
	own := makeTestCA(t, dir, "Lab Tenant Device Issuing CA", 31)
	foreign := makeTestCA(t, dir, "Northwind Device Issuing CA", 32)
	regPath := writeRegistry(t, dir, map[string]string{
		"tenant_reference_lab": own.pemPath,
		"tenant_northwind":     foreign.pemPath,
	})
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}

	ownChains := leafSignedBy(t, own, "conn_lab_001", reg.Pool)
	if ownChains == nil {
		t.Fatal("the connector's own certificate should verify against the registry pool")
	}
	// The same connector id, signed by a DIFFERENT organization's CA that this Edge also accepts.
	foreignChains := leafSignedBy(t, foreign, "conn_lab_001", reg.Pool)
	if foreignChains == nil {
		t.Fatal("the foreign certificate should verify against the registry pool — that is the whole problem")
	}

	bound, _, present := connectorMTLSIdentityBoundToTenant(
		connectorRequestPresenting(ownChains), "conn_lab_001", "tenant_reference_lab", reg)
	if !present || !bound {
		t.Fatalf("a connector presenting a certificate from its OWN organization's CA was not bound "+
			"(present=%v bound=%v)", present, bound)
	}

	bound, certIdentity, present := connectorMTLSIdentityBoundToTenant(
		connectorRequestPresenting(foreignChains), "conn_lab_001", "tenant_reference_lab", reg)
	if !present {
		t.Fatalf("a presented certificate was not seen at all")
	}
	if bound {
		t.Fatalf("a certificate naming %q was accepted for tenant_reference_lab's connector even though it was "+
			"issued by ANOTHER organization's CA — a connector belongs to one organization, so its identity has "+
			"to come from that organization's PKI", certIdentity)
	}

	// And a connector whose organization is UNKNOWN must not be bound either. That is precisely the case where
	// a certificate from anywhere would otherwise pass, so "we do not know" has to refuse rather than wave
	// through — the same reading of absence this codebase applies everywhere else.
	if bound, _, present := connectorMTLSIdentityBoundToTenant(
		connectorRequestPresenting(ownChains), "conn_lab_001", "", reg); !present || bound {
		t.Fatalf("a connector whose organization is unknown was bound to a certificate anyway "+
			"(present=%v bound=%v)", present, bound)
	}
}

// Presenting nothing must not be the easy way in. The check that binds a certificate to its connector and
// organization only ever ran when a certificate was there, so a caller offering none skipped it and the
// shared secret was the whole of the authentication.
func TestPresentingNoCertificateIsNotTheWeakerPath(t *testing.T) {
	previous := connectorMTLSPresentationRelaxed
	defer func() { connectorMTLSPresentationRelaxed = previous }()

	line := setConnectorMTLSPresentationRelaxed(false, false)
	if connectorMTLSPresentationRelaxed {
		t.Fatalf("presentation is relaxed by default: %q", line)
	}
	if !strings.Contains(line, "required") {
		t.Fatalf("the startup line does not say a certificate is required: %q", line)
	}

	// The exception exists, and saying it out loud is the price of it.
	line = setConnectorMTLSPresentationRelaxed(true, false)
	if !connectorMTLSPresentationRelaxed {
		t.Fatalf("the declared exception did not take effect")
	}
	for _, phrase := range []string{"NOT required", "shared connector secret", "declared exception"} {
		if !strings.Contains(line, phrase) {
			t.Fatalf("the startup line for the exception does not mention %q: %q", phrase, line)
		}
	}

	// lab-mode implies it, and says which of the two reasons is in force.
	line = setConnectorMTLSPresentationRelaxed(false, true)
	if !connectorMTLSPresentationRelaxed || !strings.Contains(line, "-lab-mode") {
		t.Fatalf("lab-mode did not relax presentation, or did not say so: %q", line)
	}
}

// The refusal has to be in the authorization path, not merely available. Read from the source, because a
// helper nobody calls is how this exact class of gap survives.
func TestTheConnectorPathRefusesAnAbsentCertificate(t *testing.T) {
	data, err := os.ReadFile("connector_runtime.go")
	if err != nil {
		t.Fatalf("read connector runtime: %v", err)
	}
	source := stripGoComments(string(data))
	if !strings.Contains(source, "connectorMTLSIdentityBoundToTenant(") {
		t.Fatalf("the connector authorization path does not bind the certificate to the connector's own " +
			"organization")
	}

	// Behavioural, not textual: a source check for the refusal survives being disabled in place (`false &&`),
	// which is exactly the edit somebody makes when a test is in the way. So run the path.
	previous := connectorMTLSPresentationRelaxed
	defer func() { connectorMTLSPresentationRelaxed = previous }()

	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_lab_001", TenantID: "tenant_reference_lab", Status: "active",
		PrivateBaseURL: "https://internal.example",
	}, time.Now()); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	call := func() int {
		r := httptest.NewRequest(http.MethodGet, "/connectors/conn_lab_001/effective-routes", nil)
		r.Header.Set(connectorIDHeader, "conn_lab_001")
		r.Header.Set(connectorSecretHeader, "shared-secret")
		rec := httptest.NewRecorder()
		authorizeConnectorRuntimeRequest(rec, r, "shared-secret", registry, "conn_lab_001",
			"tenant_reference_lab", false, nil)
		return rec.Code
	}

	connectorMTLSPresentationRelaxed = false
	if code := call(); code != http.StatusUnauthorized {
		t.Fatalf("a caller that presented no certificate was answered %d, want 401 — offering less is still "+
			"the easier way in", code)
	}
	// And the declared exception genuinely lets a lab through, or the flag is decoration.
	connectorMTLSPresentationRelaxed = true
	if code := call(); code == http.StatusUnauthorized {
		t.Fatalf("the declared exception did not let a certificate-less connector through, so a lab cannot run")
	}
}

// relaxConnectorMTLSPresentationForTest puts a test into the world where a connector authenticates by secret
// alone — the lab world. Tests about SECRET handling belong there; they are not statements that presenting
// nothing is acceptable on a serving node, and the gates above hold that separately.
func relaxConnectorMTLSPresentationForTest(t *testing.T) {
	t.Helper()
	previous := connectorMTLSPresentationRelaxed
	connectorMTLSPresentationRelaxed = true
	t.Cleanup(func() { connectorMTLSPresentationRelaxed = previous })
}
