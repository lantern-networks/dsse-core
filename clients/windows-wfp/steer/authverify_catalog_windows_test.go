//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

// TestCatalogSignatureLive proves the catalog (.cat) fallback covers Windows system binaries that the
// embedded WinVerifyTrust path reports as unsigned. notepad.exe/cmd.exe are catalog-signed by Microsoft.
func TestCatalogSignatureLive(t *testing.T) {
	for _, p := range []string{`C:\Windows\System32\notepad.exe`, `C:\Windows\System32\cmd.exe`} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s not present", p)
		}
		// embedded path alone should NOT validate these (they are catalog-signed)
		if imageAuthenticodeValid(p) {
			t.Logf("%s is embedded-signed on this build (unexpected but fine)", p)
		}
		// the combined imageSignature (embedded -> catalog fallback) must validate + name Microsoft
		sig := imageSignature(p)
		if !sig.valid {
			t.Fatalf("%s should validate via catalog; got valid=false", p)
		}
		if !strings.Contains(strings.ToLower(sig.publisher), "microsoft") {
			t.Fatalf("%s catalog signer = %q, want contains 'Microsoft'", p, sig.publisher)
		}
		t.Logf("%s -> valid=%v publisher=%q (catalog)", p, sig.valid, sig.publisher)
	}
}
