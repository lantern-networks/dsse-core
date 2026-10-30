package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The optional Burn bundle consumes the MSI produced by the sibling script.
// On a non-Windows review host this catches their path/version drift before a
// signing round, without pretending to execute WiX or the EV token.
func TestBundleUsesTheMSIBuildOutputAndResolvesVersionInScriptScope(t *testing.T) {
	for _, name := range []string{"build-msi.ps1", "build-bundle.ps1"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		if !regexp.MustCompile(`(?m)^\$repo\s*=\s*\$oss\b`).MatchString(source) {
			t.Errorf("%s must use the OSS root as the shared outputs directory", name)
		}
		if !strings.Contains(source, `Join-Path $repo "outputs\windows"`) {
			t.Errorf("%s must place/consume the MSI in the shared outputs/windows directory", name)
		}
		if !strings.Contains(source, `[string] $Version = ""`) {
			t.Errorf("%s must defer default version resolution until script scope is available", name)
		}
		body := strings.Index(source, "$ErrorActionPreference = 'Stop'")
		lookup := strings.Index(source, "if (-not $Version) {")
		if body < 0 || lookup <= body {
			t.Errorf("%s must resolve VERSION after the parameter block", name)
		}
	}
}
