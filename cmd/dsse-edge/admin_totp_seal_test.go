package main

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

func TestTOTPSecretSealRoundTrip(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // sample base32 TOTP secret

	// No KEK configured: pass-through (backwards compatible).
	edgeplane.SetInterceptionRootKEK(nil)
	if sealed, err := sealTOTPSecretForStore(secret); err != nil || sealed != secret {
		t.Fatalf("no KEK: want pass-through %q, got %q err=%v", secret, sealed, err)
	}

	// With a KEK: sealed value is prefixed, not equal to plaintext, and unseals back.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	edgeplane.SetInterceptionRootKEK(kek)
	defer edgeplane.SetInterceptionRootKEK(nil)

	sealed, err := sealTOTPSecretForStore(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.HasPrefix(sealed, sealedTOTPSecretPrefix) {
		t.Fatalf("sealed value missing prefix: %q", sealed)
	}
	if strings.Contains(sealed, secret) {
		t.Fatalf("plaintext secret leaked into sealed value: %q", sealed)
	}
	got, err := unsealTOTPSecretFromStore(sealed)
	if err != nil || got != secret {
		t.Fatalf("unseal: want %q, got %q err=%v", secret, got, err)
	}

	// Idempotent: sealing an already-sealed value is a no-op.
	if again, err := sealTOTPSecretForStore(sealed); err != nil || again != sealed {
		t.Fatalf("double-seal not idempotent: %q err=%v", again, err)
	}

	// Empty (not-yet-enrolled) stays empty.
	if out, err := sealTOTPSecretForStore(""); err != nil || out != "" {
		t.Fatalf("empty seal: got %q err=%v", out, err)
	}

	// Fail-closed: a sealed value with no KEK must error, never silently return garbage.
	edgeplane.SetInterceptionRootKEK(nil)
	if _, err := unsealTOTPSecretFromStore(sealed); err == nil {
		t.Fatalf("sealed value with no KEK must fail closed")
	}
}
