package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// plan_pin_matches_the_verifier_test.go — the build must not refuse a key the device would accept.
//
// ★ IT DID (2026-08-12, found by trying the reference lab's real agent-policy key). build-msi.ps1 required
// exactly 64 hex characters — an Ed25519 key — and the Edge signs with an ECDSA-P256 key held in a PKCS#11
// token, which is 130 characters and is what its own startup line hands the operator to anchor. So the one
// value a real deployment has could not be built into a package.
//
// The macOS side had just fixed the same drift one step later: the flag's help string said "Ed25519" while
// agentpolicy.AcceptedPublicKeyHex took either. Three places have to agree — the help, the build, and the
// verifier — and the verifier is the one that decides, so it is the one this test asks.

// planPinPattern lifts the regex out of build-msi.ps1 rather than restating it, so a change there is a change
// here. A test carrying its own copy of the rule cannot catch the rule drifting.
func planPinPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("build-msi.ps1")
	if err != nil {
		t.Fatalf("read build-msi.ps1: %v", err)
	}
	m := regexp.MustCompile(`\$PlanPin -notmatch '\^\(([^']+)\)\$'`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("could not find the -PlanPin validation in build-msi.ps1; if it moved, this test has to follow it " +
			"rather than be deleted — the build refusing a valid key is invisible until somebody has one")
	}
	return regexp.MustCompile(`^(` + m[1] + `)$`)
}

func TestTheBuildAcceptsEveryKeyShapeTheVerifierDoes(t *testing.T) {
	re := planPinPattern(t)
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"Ed25519, 32 bytes", strings.Repeat("ab", 32)},
		// The reference Edge's agent-policy key: an uncompressed P-256 point, which is what a PKCS#11 token
		// holds and what the Edge prints at startup for the operator to anchor.
		{"ECDSA-P256 uncompressed point, 65 bytes", "045dfd4ea0551351709095846afc1e241b74ad4ab5fa91ed02905b6d" +
			"2722cbd00e65571248acb788ece8d8801a8e5a643be2758096baa7babd79f4e5c4527e3315"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !agentpolicy.AcceptedPublicKeyHex(tc.key) {
				t.Skipf("the verifier does not accept this shape, so the build need not either: %s", tc.name)
			}
			if !re.MatchString(tc.key) {
				t.Fatalf("build-msi.ps1 REFUSES a %s key that agentpolicy accepts. A deployment holding that key "+
					"cannot build a package at all, and the failure names the wrong reason.", tc.name)
			}
		})
	}
}

// And it must not accept what the verifier would refuse: a build that bakes a key no device can use produces a
// fleet that verifies nothing, discovered on the first signed document rather than at build time.
func TestTheBuildRefusesWhatTheVerifierRefuses(t *testing.T) {
	re := planPinPattern(t)
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"too short", strings.Repeat("ab", 16)},
		{"65 bytes but not an uncompressed point", strings.Repeat("aa", 65)},
		{"not hex", strings.Repeat("zz", 32)},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if agentpolicy.AcceptedPublicKeyHex(tc.key) {
				t.Skipf("the verifier accepts this after all: %s", tc.name)
			}
			if re.MatchString(tc.key) {
				t.Fatalf("build-msi.ps1 ACCEPTS a %s key the verifier refuses; the package would ship a pin no "+
					"device can use", tc.name)
			}
		})
	}
}
