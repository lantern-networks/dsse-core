package main

import "testing"

// GAP-1 (device-facing paths): the Windows WFP / macOS device agents reach every one of CONNECT /steer,
// POST /dns/strip-ech, POST /devices/register and POST /devices/{id}/heartbeat over the (T) transport mTLS,
// where the cert was VERIFIED and admitted against the enrolled inventory. Those handlers are also served on
// the plaintext :8443 listener, so they keep connector authorization for non-transport callers but EXEMPT a
// verified transport-device request (the device is authenticated, not a connector). All four use the SAME
// discriminator this test pins; the audit of every connector-gated endpoint confirmed these are the complete
// set the agent calls (the other /devices/* endpoints are admin-facing / not agent-called). Before this, removing -lab-mode 401'd every steered device on /steer because it carries no
// connector credentials. The exemption is driven by transportDeviceIdentityFromRequest, which is verified=true
// ONLY for a verified mTLS chain — this test pins that discriminator (the security-critical part: a plaintext
// request must NOT be treated as transport-authenticated, or the connector gate would be bypassable on :8443).
func TestTransportDeviceIdentityDiscriminatorForSteerGate(t *testing.T) {
	// Verified mTLS transport request (what the device agent presents on :18543) -> exempt from connector auth.
	if id, verified := transportDeviceIdentityFromRequest(reqWithClientCertCN("win-dev-1")); !verified || id != "win-dev-1" {
		t.Fatalf("verified mTLS request: got id=%q verified=%v, want (\"win-dev-1\", true) — the steered device "+
			"must be recognized as transport-authenticated so it skips the connector gate", id, verified)
	}

	// Plaintext request (the :8443 listener has no client cert) -> NOT transport-authenticated -> the connector
	// gate still applies. This is the security-critical half: it must be false, else /steer is open on :8443.
	if id, verified := transportDeviceIdentityFromRequest(reqWithClientCertCN("")); verified || id != "" {
		t.Fatalf("plaintext request: got id=%q verified=%v, want (\"\", false) — a non-mTLS caller must NOT be "+
			"treated as transport-authenticated (the connector gate must still protect /steer on :8443)", id, verified)
	}
}
