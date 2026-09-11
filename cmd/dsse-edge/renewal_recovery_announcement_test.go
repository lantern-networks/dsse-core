package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// ★★★ A NAME THAT IS NOT SERVED MUST NOT BE ANNOUNCED (2026-08-19).
//
// The trust bundle carries renewal_recovery_sni to every device, and the agents use it to choose the folded
// path over the dedicated port. Announcing it while the transport port answers that name with a certificate
// that does not carry it sends every expiring device down a path it must refuse — and those devices are, by
// definition, the ones already unable to reach anything else.
func TestTheRecoveryNameIsAnnouncedOnlyWhileItIsServed(t *testing.T) {
	prev := renewalRecoveryMainPort.Load()
	t.Cleanup(func() { renewalRecoveryMainPort.Store(prev) })

	renewalRecoveryMainPort.Store(nil)
	if got := offeredRenewalRecoverySNI("recovery.dsse.invalid"); got != "" {
		t.Fatalf("a name was announced while nothing serves it: %q — every device that believes it loses its "+
			"only way back once its certificate expires", got)
	}

	renewalRecoveryMainPort.Store(&renewalRecoveryOnMainPort{
		sni:    "recovery.dsse.invalid",
		mux:    http.NewServeMux(),
		verify: func(tls.ConnectionState) error { return nil },
	})
	if got := offeredRenewalRecoverySNI("Recovery.DSSE.Invalid"); got != "recovery.dsse.invalid" {
		t.Fatalf("the name that IS served was not announced (%q) — the fold could never be measured or closed", got)
	}

	// Configured one way, served another: the device must be told what is served, and nothing else.
	if got := offeredRenewalRecoverySNI("other.dsse.invalid"); got != "" {
		t.Fatalf("a name nobody serves was announced: %q", got)
	}
}
