package main

import "flag"

// audit_ingest_identity_flags.go — the certificate an Edge presents when it ships records to the control plane.
//
// ★ WITHOUT IT THE CONTROL PLANE CANNOT TELL WHICH EDGE SENT WHAT (2026-08-12, tenth review). The receiver
// derives the sending Edge's tenant from the certificate it presents and refuses a record naming a different
// one — and the shipper presented none, so that check reached its lenient branch on every real shipment and
// the shared bearer was the only control while the code read as though it were not.
//
// In a sibling file because the decomposition ratchet says new flags go in one, and it is right: this is a
// pair of settings with one reason for existing, and main.go is where they would become invisible.
type auditIngestIdentityFlags struct {
	cert      *string
	key       *string
	authority *string
	clientCAs *string
}

func registerAuditIngestIdentityFlags() auditIngestIdentityFlags {
	return auditIngestIdentityFlags{
		cert: flag.String("audit-ingest-client-cert", "", "PEM certificate this Edge presents to the audit-ingest endpoint, so the control plane can bind shipped records to this Edge's tenant. Empty means the control plane cannot attribute them, and outside -lab-mode it refuses the shipment"),
		key:  flag.String("audit-ingest-client-key", "", "private key for -audit-ingest-client-cert"),
		// ★ AN EDGE SERVES SEVERAL TENANTS AND SHIPS THEM ALL FROM ONE SPOOL, so the certificate answers "which
		// EDGE is this" and this answers "which tenants may it ship for". Binding the record's tenant to the
		// certificate's tenant — the first version — would have forbidden every record but one tenant's.
		// ★ SEPARATE FROM THE TENANT CA REGISTRY, and that separation is the design correction. An Edge's
		// identity is issued by the OPERATOR, not by a tenant's CA — one Edge serves several tenants — so the
		// anchors it is verified against are the operator's. Without this the listener requests no client
		// certificate at all and the binding cannot exist.
		clientCAs: flag.String("audit-ingest-client-ca", "", "PEM anchors the control plane verifies a shipping Edge's client certificate against (operator-issued edge identities). Empty means no client certificate is requested, and shipments cannot be attributed to an edge"),
		// ★ IT IS A PATH, AND THE HELP USED TO SHOW THE CONTENT (2026-08-24, found by passing the content). A
		// flag whose help reads like a value and whose code opens a file produces a start-up failure that
		// names the JSON as a missing filename — which is exactly as confusing as it sounds.
		authority: flag.String("audit-ingest-authority", "", `PATH to a JSON file mapping edge identity (client-certificate CN) to the tenants it may ship audit records for, e.g. {"edge-tokyo-1":["tenant_a","tenant_b"]}. "*" authorises all. Empty means an edge may ship only for the tenant its certificate was issued by, which is the single-tenant deployment`),
	}
}
