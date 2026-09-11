package main

import (
	"strings"
	"testing"
)

// ★★★ A VALUE THAT STARTS WITH "-" STOPS BEING A VALUE the moment anything passes it as an argument. Measured
// 2026-09-02 on a deployment that stood up correctly and whose hot store was dead at boot:
//
//	Code: 552. DB::Exception: Unrecognized option '-H9ekhsO1gSO_nlvY5d7hWMa34wGmG5x'.
//
// base64url includes "-", so about one secret in thirty-two begins with one. Sixty-four draws would miss that
// with probability (31/32)^64 ≈ 0.13, which is not a test; ten thousand makes it certain enough to mean
// something and still costs nothing.
func TestAMintedSecretNeverLooksLikeAnOption(t *testing.T) {
	for i := 0; i < 10000; i++ {
		s := randomSecret()
		if strings.HasPrefix(s, "-") {
			t.Fatalf("draw %d minted %q, which every argv in this deployment will read as a flag", i, s)
		}
		if len(s) < 24 {
			t.Fatalf("draw %d minted %q, which is shorter than the entropy it is supposed to carry", i, s)
		}
	}
}
