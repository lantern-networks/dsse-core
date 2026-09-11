package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// observedWithPins answers Query with one report per device, so the gate can be asked about a fleet that has
// moved to per-organization authorities. TransportCAReadiness still says "nobody has confirmed the shared
// anchor", which is the true state after roadmap D and the state that used to block every withdrawal.
type observedWithPins struct {
	fakeObserved
	tenant   string
	pins     map[string][]string
	reported map[string]time.Time
}

func (o observedWithPins) Query(_ string, f observedQueryFilter) observedQueryResult {
	id := strings.TrimSpace(f.Device)
	pins, ok := o.pins[id]
	if !ok {
		return observedQueryResult{}
	}
	at, has := o.reported[id]
	if !has {
		at = time.Now()
	}
	return observedQueryResult{Entries: []observedExclusionEntry{{
		TenantID: o.tenant, DeviceIdentity: id, PinnedTransportCASHA256: pins, ReportedAt: at,
	}}, Total: 1}
}

// ★★★ AFTER ROADMAP D NOTHING COULD BE WITHDRAWN (2026-08-20, measured on the lab). Both real devices report
// pinning their organization's own transport CA and neither pins the shared anchor, so no certificate in the
// shared store was "trusted by every device": twenty-two attempts over eighteen minutes, every one refused
// "unconfirmed: mac-dev-1, win-dev-1", with both devices healthy and reporting the CURRENT serial.
func TestADeviceOnItsOwnOrganizationsAuthorityDoesNotBlockAWithdrawal(t *testing.T) {
	target, served := gateFixture(t)
	own := parseAllCerts(testCertPEM(t, "the-organizations-own-transport-ca"))[0]

	prevTrust, prevServed, prevTenantCerts := transportTrust, transportServedCert, transportTenantCertificates
	transportTrust, transportServedCert = &transportTrustStore{}, nil
	transportTenantCertificates = &transportTenantCerts{
		tenantOf: map[string]string{"lab.dsse.invalid": "tenant_lab"},
		anchorOf: map[string]string{"tenant_lab": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: own.Raw}))},
	}
	defer func() {
		transportTrust, transportServedCert, transportTenantCertificates = prevTrust, prevServed, prevTenantCerts
	}()

	dir := t.TempDir()
	path := dir + "/transport.pem"
	writePEM(t, path, served)
	base := fakeObserved{ready: map[string][]string{}} // nobody confirms anything in the shared store

	cfg := serverConfig{TransportCertFile: path, ObservedExclusions: observedWithPins{
		fakeObserved: base, tenant: "tenant_lab",
		pins: map[string][]string{"mac-dev-1": {certFingerprint(own)}},
	}}
	anchors := []*x509.Certificate{target, served}

	ok, verdict := anchorWithdrawGate(cfg, "tenant_lab", certFingerprint(target), anchors, []string{"mac-dev-1"}, 1)
	if !ok {
		t.Fatalf("a device that pins its own organization's authority still blocked the withdrawal: %q", verdict.Text)
	}

	// A stale report is silence. The machine may have been re-imaged since.
	stale := observedWithPins{fakeObserved: base, tenant: "tenant_lab",
		pins:     map[string][]string{"mac-dev-1": {certFingerprint(own)}},
		reported: map[string]time.Time{"mac-dev-1": time.Now().Add(-2 * transportCAReportShelfLife)}}
	if ok, _ := anchorWithdrawGate(serverConfig{TransportCertFile: path, ObservedExclusions: stale},
		"tenant_lab", certFingerprint(target), anchors, []string{"mac-dev-1"}, 1); ok {
		t.Fatal("a stale report opened the gate")
	}

	// A device pinning something this node does not serve stays in the denominator.
	elsewhere := observedWithPins{fakeObserved: base, tenant: "tenant_lab",
		pins: map[string][]string{"mac-dev-1": {certFingerprint(target)}}}
	if ok, _ := anchorWithdrawGate(serverConfig{TransportCertFile: path, ObservedExclusions: elsewhere},
		"tenant_lab", certFingerprint(target), anchors, []string{"mac-dev-1"}, 1); ok {
		t.Fatal("a device pinning a certificate this node does not serve opened the gate")
	}

	// A device that has reported nothing at all is exactly who this gate protects.
	silent := observedWithPins{fakeObserved: base, tenant: "tenant_lab", pins: map[string][]string{}}
	if ok, _ := anchorWithdrawGate(serverConfig{TransportCertFile: path, ObservedExclusions: silent},
		"tenant_lab", certFingerprint(target), anchors, []string{"mac-dev-1"}, 1); ok {
		t.Fatal("a silent device opened the gate")
	}

	// And the chain condition is untouched: with nothing remaining that verifies what the Edge presents,
	// the withdrawal is still refused however well covered the fleet is.
	other := parseAllCerts(testCertPEM(t, "unrelated"))[0]
	if ok, _ := anchorWithdrawGate(cfg, "tenant_lab", certFingerprint(served),
		[]*x509.Certificate{served, other}, []string{"mac-dev-1"}, 1); ok {
		t.Fatal("the gate allowed removing the only certificate that verifies the served identity")
	}
}
