package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ★★★ THE LAST RESORT WAS ALIVE FOR ONE ORGANIZATION AND DEAD FOR EVERY OTHER (2026-08-20, measured).
//
// GET /bootstrap/trust-bundle is served without device authentication on purpose: it runs when a device cannot
// prove who it is, and the document's authenticity comes from its signature. It also accepted ?tenant= so such
// a device could say which organization it belongs to — and NO AGENT SENDS IT. Not macOS, not Windows, not the
// fetch helper both share.
//
// So every device that reached this endpoint for the reason it exists was handed THE NODE'S organization's
// distribution. Measured on the lab: a device of tenant_northwind receives tenant_reference_lab's single
// anchor, and openssl confirms that anchor cannot verify the certificate the Edge presents for
// northwind.dsse.invalid. It refuses, correctly, and never recovers. Nothing in a single-organization
// deployment can show that.
//
// The name is what a device always has — it is in the distribution it adopted and it is what it dials — so it
// now selects, from the query or from the handshake. It is not a credential and proves nothing.
func TestTheRecoveryBundleAnswersTheOrganizationThatNamedItself(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}

	// Named in the query, which is the form an agent fetching over an ordinary HTTPS client can use.
	asked := httptest.NewRequest(http.MethodGet, "/bootstrap/trust-bundle?server_name=Northwind.DSSE.Invalid", nil)
	if got := tenantForServedName(asked, asked.URL.Query().Get("server_name")); got != "tenant_northwind" {
		t.Fatalf("a device that named itself was not recognised: %q", got)
	}

	// Named in the handshake, which is what a device dialling the name sends anyway.
	dialled := httptest.NewRequest(http.MethodGet, "/bootstrap/trust-bundle", nil)
	dialled.TLS = &tls.ConnectionState{ServerName: "northwind.dsse.invalid"}
	if got := tenantForServedName(dialled, ""); got != "tenant_northwind" {
		t.Fatalf("the name this caller dialled was ignored: %q", got)
	}

	// A name this node does not serve selects nothing — it must not become a way to ask about an organization
	// that is not here, and the caller falls back to the deployment's own answer exactly as before.
	unknown := httptest.NewRequest(http.MethodGet, "/bootstrap/trust-bundle", nil)
	unknown.TLS = &tls.ConnectionState{ServerName: "somebody.else.invalid"}
	if got := tenantForServedName(unknown, ""); got != "" {
		t.Fatalf("a name this node does not serve resolved to %q", got)
	}

	// And no name at all is unchanged: every caller before this got the deployment's own answer.
	plain := httptest.NewRequest(http.MethodGet, "/bootstrap/trust-bundle", nil)
	if got := tenantForServedName(plain, ""); got != "" {
		t.Fatalf("a caller that named nothing resolved to %q", got)
	}
}
