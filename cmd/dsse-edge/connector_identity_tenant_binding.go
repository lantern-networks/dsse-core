package main

import (
	"flag"
	"net/http"
	"strings"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"
)

// connectorMTLSIdentityBoundToTenant reports whether the certificate on this connection is the certificate of
// THIS connector, in THIS organization.
//
// ★ WHY THE ORGANIZATION IS PART OF THE QUESTION (operator, 2026-08-19). A CONNECTOR BELONGS TO EXACTLY ONE
// ORGANIZATION — unlike an Edge, which serves several and therefore accepts several organizations' device
// CAs. The check this replaces compared only the certificate's common name to the connector id, so any
// organization whose CA this Edge accepts could mint a certificate naming another organization's connector
// and be bound to it. Demonstrated by a test that failed before this existed.
//
// The organization is taken from the ISSUING CA via the tenant CA registry — never from a header, a body or
// the certificate's own subject fields — which is the same rule the transport already uses to key a flow to
// its organization. A certificate that chains to no registered CA resolves to no organization and is not
// bound, because "this Edge happens to trust the issuer" is not the same claim as "this organization issued
// it".
func connectorMTLSIdentityBoundToTenant(r *http.Request, connectorID, connectorTenant string, reg *tenantca.TenantCARegistry) (bound bool, certIdentity string, present bool) {
	nameBound, identity, presented := connectorMTLSIdentityBound(r, connectorID)
	if !presented {
		return false, identity, false
	}
	if !nameBound {
		return false, identity, true
	}
	// No registry, no tenant to compare against. Reporting "bound" here keeps the pre-existing behaviour of a
	// deployment that has no tenant CA registry at all, where every accepted CA is the one deployment's own.
	if reg == nil {
		return true, identity, true
	}
	expected := strings.TrimSpace(connectorTenant)
	if expected == "" {
		// A connector whose organization is unknown cannot have its certificate checked against it. Refusing
		// is the honest answer: this is precisely the case where a certificate from anywhere would pass.
		return false, identity, true
	}
	certTenant, ok := transportTenantFromRequest(r, reg)
	if !ok {
		return false, identity, true
	}
	return strings.EqualFold(strings.TrimSpace(certTenant), expected), identity, true
}

// connectorMTLSNotRequiredFlag is the declared exception to certificate presentation. It lives beside the
// binding rule it weakens rather than in main.go, both because the decomposition ratchet asks for that and
// because somebody reading the rule should meet its escape hatch in the same file.
var connectorMTLSNotRequiredFlag = flag.Bool("connector-mtls-not-required", false,
	"allow a connector to authenticate WITHOUT presenting a certificate issued by its own organization's device CA, "+
		"leaving the shared connector secret as the whole of its authentication. Off by default; -lab-mode implies it")
