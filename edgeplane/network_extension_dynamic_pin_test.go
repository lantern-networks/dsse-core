package edgeplane

import (
	"testing"
	"time"
)

// Unit tests for dynamic certificate-pinning detection: a destination whose intercepted handshakes fail
// consecutively is learned and switched to a raw forward; a successful handshake resets the failure count so
// nothing is pinned by mistake; and a static bypass wins over anything the pin learning concluded.
func TestDynamicPinDetectionLearnsAndRawForwards(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	// decrypt-all ('*') deciding from the SNI: without pin detection every host is intercepted.
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	// Auto-pin is off by default as a fail-safe. This test is about that behaviour, so it enables it
	// explicitly.
	interception.SetDynamicPinDetectionEnabled(true)

	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "17.253.1.1", Port: 443, SNI: "gateway.icloud.com"}

	// It starts intercepted, under decrypt-all.
	if !interception.Matches(route) {
		t.Fatalf("expected intercept before any pin learning")
	}

	// One handshake failure: below the threshold of two, so nothing is pinned yet.
	if interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("should not pin after a single failure (threshold=2)")
	}
	if !interception.Matches(route) {
		t.Fatalf("expected still-intercept after one failure")
	}

	// A second consecutive failure reaches the threshold and the destination is pinned; true because this is
	// the first time.
	if !interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("expected newly-pinned=true on reaching threshold")
	}
	// From here it is raw-forwarded.
	if interception.Matches(route) {
		t.Fatalf("expected raw_forward (Matches=false) after pin learned")
	}
	// Already pinned, so a further failure reports newly-pinned as false.
	if interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("expected newly-pinned=false when already pinned")
	}
}

// With the production default — auto-pin off — detection still runs and proposes the destination as a bypass
// candidate, and nothing is raw-forwarded automatically. That is what makes the candidate workflow safe: an
// attacker who fails handshakes cannot get themselves bypassed.
func TestCertPinDetectionProposesButNeverAutoBypassesWhenDisabled(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	// The production wiring: auto-pin off, detection and candidate proposal still on.
	interception.SetDynamicPinDetectionEnabled(false)

	var proposed []string
	interception.SetCertPinCandidateEmitter(func(host string) { proposed = append(proposed, host) })

	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "17.253.1.1", Port: 443, SNI: "gateway.icloud.com"}
	if !interception.Matches(route) {
		t.Fatalf("expected intercept before any detection")
	}

	// Even failing consecutively to the threshold, newly-pinned stays false while auto-pin is off.
	if interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("auto-pin disabled: must not pin on first failure")
	}
	if interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("auto-pin disabled: must not auto-bypass on reaching threshold")
	}
	// The destination is still intercepted: a candidate bypasses nothing until an administrator approves it.
	if !interception.Matches(route) {
		t.Fatalf("auto-pin disabled: host must stay intercepted (proposal != bypass)")
	}
	// Detection ran, though, and a bypass candidate was proposed.
	if len(proposed) == 0 || proposed[len(proposed)-1] != "gateway.icloud.com" {
		t.Fatalf("expected a bypass-candidate proposal on threshold, got %v", proposed)
	}
}

// On a lab or debug path that enables auto-pin explicitly, reaching the threshold raw-forwards the
// destination AND proposes the candidate.
func TestCertPinDetectionAutoBypassesWhenEnabled(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	interception.SetDynamicPinDetectionEnabled(true) // OPT-IN auto raw_forward

	var proposed []string
	interception.SetCertPinCandidateEmitter(func(host string) { proposed = append(proposed, host) })

	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "17.253.1.1", Port: 443, SNI: "gateway.icloud.com"}
	_ = interception.recordHandshakeOutcome("gateway.icloud.com", false)
	if !interception.recordHandshakeOutcome("gateway.icloud.com", false) {
		t.Fatalf("auto-pin enabled: expected newly-pinned=true on threshold")
	}
	if interception.Matches(route) {
		t.Fatalf("auto-pin enabled: expected raw_forward after threshold")
	}
	if len(proposed) == 0 {
		t.Fatalf("expected a bypass-candidate proposal even when auto-pin is enabled")
	}
}

// A single transient failure followed by a success pins nothing, so a decryptable host is not pinned by
// mistake.
func TestDynamicPinDetectionResetsOnHandshakeSuccess(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "142.250.0.0", Port: 443, SNI: "accounts.google.com"}

	// Failure, then a success that resets it, then failure again: nothing is pinned while the threshold is
	// never reached consecutively.
	if interception.recordHandshakeOutcome("accounts.google.com", false) {
		t.Fatalf("unexpected pin on first failure")
	}
	interception.recordHandshakeOutcome("accounts.google.com", true) // a success resets the count
	if interception.recordHandshakeOutcome("accounts.google.com", false) {
		t.Fatalf("count must reset on success; single failure should not pin")
	}
	if !interception.Matches(route) {
		t.Fatalf("decryptable host must remain intercepted (not falsely pinned)")
	}
}

// A static bypass is always raw-forwarded, whatever the pin learning concluded: it wins.
func TestStaticBypassTakesPrecedenceOverInterceptAndPin(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	interception.SetBypassHosts([]string{"*.anthropic.com"})
	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "1.2.3.4", Port: 443, SNI: "api.anthropic.com"}
	if interception.Matches(route) {
		t.Fatalf("static bypass host must never be intercepted")
	}
}

// A destination whose intercepted handshake has succeeded once is never pinned afterwards, however many
// consecutive failures follow — which is what stops an EOF from Chrome abandoning a preconnect, or from
// steering churn, pinning a perfectly decryptable host.
func TestDynamicPinDetectionNeverPinsHostThatEverSucceeded(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	route := NetworkExtensionRuntimeCopyTCPRoute{Host: "142.250.0.0", Port: 443, SNI: "accounts.google.com"}

	// One successful interception settles it as decryptable.
	interception.recordHandshakeOutcome("accounts.google.com", true)
	// Consecutive failures from churn afterwards pin nothing.
	for i := 0; i < 5; i++ {
		if interception.recordHandshakeOutcome("accounts.google.com", false) {
			t.Fatalf("must never pin a host that ever succeeded (failure %d)", i+1)
		}
	}
	if !interception.Matches(route) {
		t.Fatalf("ever-succeeded host must remain intercepted (not falsely pinned)")
	}
}

// Disabling dynamic pin detection — the default — pins nothing however many handshakes fail, and clears any
// pin already learned. That closes the hole where an attacker fails handshakes to get raw-forwarded; bypass
// then comes from the static list alone.
func TestDynamicPinDetectionCanBeDisabled(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	// Pin it first with detection enabled; auto-pin is off by default, so enable it explicitly.
	interception.SetDynamicPinDetectionEnabled(true)
	interception.recordHandshakeOutcome("evil.example", false)
	interception.recordHandshakeOutcome("evil.example", false)
	if !interception.isPinnedHost("evil.example") {
		t.Fatalf("precondition: should be pinned while enabled")
	}
	// Disabling it clears the existing pin, and nothing is pinned however much fails afterwards.
	interception.SetDynamicPinDetectionEnabled(false)
	if interception.isPinnedHost("evil.example") {
		t.Fatalf("disabling must clear existing pins")
	}
	for i := 0; i < 5; i++ {
		if interception.recordHandshakeOutcome("evil.example", false) {
			t.Fatalf("disabled detection must never pin")
		}
	}
	if !interception.Matches(NetworkExtensionRuntimeCopyTCPRoute{Host: "1.2.3.4", Port: 443, SNI: "evil.example"}) {
		t.Fatalf("with detection disabled, decrypt-all host must stay intercepted (no raw_forward hole)")
	}
}
