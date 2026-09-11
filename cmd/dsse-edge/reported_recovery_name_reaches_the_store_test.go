package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/steerexclusion"
)

// ★★★ A REPORTED FIELD WITH NO READER IS THE SAME SILENCE AS NO FIELD (2026-08-19).
//
// The report handler decodes into its own request struct and copies field by field, so adding a field to the
// STORED record changes nothing at all. That is how renewal_recovery_sni_sent went unread: Windows shipped it
// in 0.2.10, macOS shipped it the same day, the Edge stored a struct that had the field — and every device
// still read as silent, because the two structs never met. Measured live: mac-dev-1 held serial 53 carrying
// the name and reported nothing.
//
// This posts the device's own JSON and asserts it arrives, which is the only version of this check that can
// fail for the real reason. Add a case here whenever a field is added to the report.
func TestWhatTheDeviceReportsReachesTheStore(t *testing.T) {
	observed := newObservedExclusionStore(0)
	handler := observedTestServer(t, steerexclusion.NewStore(), observed)

	body, _ := json.Marshal(map[string]any{
		"platform":                  "macos",
		"effective_app_signing_ids": []string{"com.x"},
		"adopted_trust_serial":      53,
		"renewal_recovery_sni_sent": "Recovery.DSSE.Invalid",
		"renewal_recovery_target":   "Edge.DSSE.Invalid:8443",
	})
	cert := leafWithCN(t, "mac-dev-1")
	req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("report rejected: HTTP %d %s", rec.Code, rec.Body.String())
	}

	entries := observed.List("t1")
	if len(entries) != 1 {
		t.Fatalf("the report did not reach the store at all: %+v", entries)
	}
	if entries[0].AdoptedTrustSerial != 53 {
		t.Fatalf("adopted_trust_serial did not survive the handler: %+v", entries[0])
	}
	if entries[0].RenewalRecoverySNISent != "recovery.dsse.invalid" {
		t.Fatalf("renewal_recovery_sni_sent did not survive the handler (%q) — the port-closing gate would "+
			"count this device as silent forever", entries[0].RenewalRecoverySNISent)
	}
	// ★ Added the day it was found missing (2026-08-20). The readiness rule required this field from
	// 2026-08-19 and the handler never read it, so every device counted as silent for ever and the fold's
	// measurement could not say "holds" about anybody — with the dedicated port already closed underneath it.
	if entries[0].RenewalRecoveryTarget != "edge.dsse.invalid:8443" {
		t.Fatalf("renewal_recovery_target did not survive the handler (%q) — the gate that asks where a device "+
			"would actually dial can never be satisfied", entries[0].RenewalRecoveryTarget)
	}
}
