package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ THE HANDSHAKE AND THE DISPATCH MUST AGREE ON WHAT A RECOVERY NAME IS (2026-08-21, FAIL reported from
// win-dev-1 running the fold for the first time with a genuinely expired certificate).
//
// recoveryConfigFor relaxed the handshake for recovery.<org> — that half followed the announcement when it
// moved off the deployment-wide name. serveRecoveryIfNamed did not: it compared the SNI to the deployment-wide
// name alone, so the connection was relaxed and then handed to the ORDINARY mux, where the identity comes from
// VerifiedChains — empty, because Go did not verify the expired certificate — and /enroll/renew answered 401
// "renewal requires a verified client certificate". Backwards: a device that could present one would not be
// here. The dedicated port was already retired, so an expired device had no path back at all.
func TestTheRecoveryFoldDispatchesAnOrganizationsOwnRecoveryName(t *testing.T) {
	reached := false
	recoveryMux := http.NewServeMux()
	recoveryMux.HandleFunc("POST /enroll/renew", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	previous := renewalRecoveryMainPort.Load()
	renewalRecoveryMainPort.Store(&renewalRecoveryOnMainPort{
		sni: "recovery.dsse.invalid",
		mux: recoveryMux,
	})
	t.Cleanup(func() { renewalRecoveryMainPort.Store(previous) })

	// The organization's own recovery name — served by this node, exactly as isRecoveryName requires. The
	// certificate itself is irrelevant here; what matters is that the name resolves to this organization.
	transportTenantCertificates.put("tenant_recovery_fold_test", []string{
		"lab.dsse.invalid", "recovery.lab.dsse.invalid", "enrol.lab.dsse.invalid",
	}, &tls.Certificate{}, "")
	t.Cleanup(func() {
		transportTenantCertificates.mu.Lock()
		defer transportTenantCertificates.mu.Unlock()
		for _, n := range []string{"lab.dsse.invalid", "recovery.lab.dsse.invalid", "enrol.lab.dsse.invalid"} {
			delete(transportTenantCertificates.bySNI, n)
			delete(transportTenantCertificates.tenantOf, n)
		}
		delete(transportTenantCertificates.anchorOf, "tenant_recovery_fold_test")
	})

	call := func(serverName string) bool {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/enroll/renew", strings.NewReader("{}"))
		req.TLS = &tls.ConnectionState{ServerName: serverName}
		fell := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { fell = true })
		if !serveRecoveryIfNamed(httptest.NewRecorder(), req) {
			next.ServeHTTP(httptest.NewRecorder(), req)
		}
		_ = fell
		return reached
	}

	if !call("recovery.lab.dsse.invalid") {
		t.Fatal("★ a device arriving under its own organization's announced recovery name was NOT dispatched " +
			"to the recovery mux. It reaches the ordinary handler instead, whose identity comes from " +
			"VerifiedChains — empty for the expired certificate this path exists to accept — so renewal " +
			"answers 401 and an expired device has no way back.")
	}
	if !call("recovery.dsse.invalid") {
		t.Fatal("the deployment-wide recovery name stopped being dispatched — the fix was supposed to ADD the " +
			"per-organization names, not replace the one every older device still sends")
	}
	// The controls: an ordinary transport connection and an unknown recovery name are left entirely alone.
	if call("lab.dsse.invalid") {
		t.Fatal("an ordinary transport handshake was sent to the recovery mux — the relaxed path must open " +
			"only for the recovery name")
	}
	if call("recovery.someone-else.dsse.invalid") {
		t.Fatal("a recovery name this node does not serve was dispatched. An unknown recovery.* must not " +
			"reach the path that accepts expired certificates.")
	}
}
