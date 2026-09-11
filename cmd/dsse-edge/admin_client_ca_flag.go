package main

import "flag"

// admin_client_ca_flag.go — the client certificates the ADMIN listener will accept at the handshake.
//
// ★★ A CREDENTIAL THIS DEPLOYMENT ISSUES ITSELF USED TO KILL THE CONNECTION (2026-08-19). The admin listener
// asks for a client certificate, and must: /audit-ingest is served here and the receiver derives the shipping
// Edge from its verified chain. Go's VerifyClientCertIfGiven then makes a certificate it CANNOT verify fatal —
// the handshake dies, no HTTP status is ever produced — and the anchors in that pool are the operator's
// edge-identity CA and the per-tenant device CAs. The Console's own admin client CA is in neither.
//
// So `curl --cert certs/admin-client.crt`, the operator's documented way in and the one boot.sh prints at the
// end of every bring-up, failed with "tlsv1 alert unknown ca" and nothing else. Removing the certificate made
// the same request work. It began when the deployment became multi-tenant: with an empty pool no certificate
// is requested at all, so the client never offered one and nothing was ever verified.
//
// Naming the CA here AUTHENTICATES NOTHING. The admin API is on sessions and tokens, and audit-ingest resolves
// a shipper through the tenant CA registry and the authority map — an admin certificate is in neither, so it
// ships nothing (audit_ingest_authority.go). What it buys is that a certificate this deployment handed out
// stops being fatal to the connection.
//
// ★ THE CLASS IS NOT CLOSED. Any OTHER client certificate — one a browser holds, one a corporate policy
// installs — still fails the handshake on this listener. Closing that means asking without verifying in TLS
// and verifying explicitly in the receiver, which is how the audit-ingest binding was broken the first time
// (edge_client_ca_pool.go). One door is shut here; the class is written down in
// docs/2026-08-19_three_doors_measured_wrong.ja.md rather than left as folklore.
//
// In a sibling file because the decomposition ratchet says new flags go in one.
func registerAdminClientCAFlag() *string {
	return flag.String("admin-client-ca", "", "PEM anchors for client certificates presented to the ADMIN listener (the Console's own admin client CA). These authenticate nothing on their own — the admin API uses sessions and tokens — but naming them here stops a certificate this deployment issued from failing the TLS handshake outright, which is what a client offering an unknown certificate does on a listener that verifies")
}
