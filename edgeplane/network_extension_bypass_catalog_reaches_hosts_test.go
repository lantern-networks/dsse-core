package edgeplane

import (
	"testing"

	"github.com/lantern-networks/dsse-core/knownbypass"
)

// The catalog and the matcher are two different files, and a pattern that is in the list but does not MATCH the
// host it was added for is indistinguishable — from the catalog's side — from one that works.
//
// Written after exactly that gap cost a working build (2026-08-10). Notarizing this product's own .pkg from a
// Mac steered by this product failed at `stapler` with a CA pinning mismatch on api.apple-cloudkit.com: the
// catalog carried nine Apple entries, the reference Edge additionally bypassed "*.apple.com" by flag, and
// apple-cloudkit.com is a different domain that neither reached. The symptom is the quiet kind — notarization
// succeeds and only the staple fails, so the artifact installs on the machine that built it and is refused on
// the offline machine it was built for.
//
// Asserted against the ENGINE's matcher rather than against the pattern string, because "the list contains
// *.apple-cloudkit.com" is not the property that matters. The property is that a flow to the concrete host
// raw-forwards.
func TestDefaultBypassCatalogActuallyMatchesTheHostsItNames(t *testing.T) {
	hosts := knownbypass.DefaultBypassHosts()

	// Concrete hosts observed in the field, each with the entry that is supposed to cover it. A host added here
	// must be one that was really seen, so this list stays evidence rather than guesswork.
	for _, tc := range []struct{ host, why string }{
		{"api.apple-cloudkit.com", "Gatekeeper notarization ticket lookup; measured breaking stapler"},
		{"mask.icloud.com", "iCloud Private Relay ingress"},
		{"gateway.push.apple.com", "APNs"},
		{"ocsp.apple.com", "Apple OCSP"},
	} {
		if !networkExtensionLabTLSHostMatchesAnyPattern(tc.host, hosts) {
			t.Errorf("the default bypass catalog does not match %q (%s) — it would be decrypted, and a pinned "+
				"client fails in a way that does not name the proxy", tc.host, tc.why)
		}
	}

	// The converse, so this test cannot pass by the catalog turning into a wildcard: a tenant-restriction
	// interception target must still be decrypted.
	for _, host := range []string{"accounts.google.com", "login.microsoftonline.com"} {
		if networkExtensionLabTLSHostMatchesAnyPattern(host, hosts) {
			t.Errorf("%q is bypassed by the default catalog, which would disable tenant restriction on it", host)
		}
	}
}
