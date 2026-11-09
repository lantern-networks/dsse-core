package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The C# that verify-windows-install.ps1 compiles with Add-Type must build on PowerShell 7 as well as 5.1
// (2026-11-06: on PowerShell 7.6, `new X509Certificate2(cert.RawData)` failed with SYSLIB0057 — the byte[]
// constructor is obsolete in .NET 9 — and the strict-TLS section could not run).
func TestTheVerifyScriptsCompiledCodeAvoidsObsoleteCertificateConstructors(t *testing.T) {
	src, err := os.ReadFile("verify-windows-install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)Add-Type -TypeDefinition @'(.*?)'@`).FindAllStringSubmatch(string(src), -1)
	if len(blocks) == 0 {
		t.Fatal("the script compiles no C# any more; this test has nothing to check")
	}
	obsolete := regexp.MustCompile(`new X509Certificate2\([^)]*(RawData|byte\[\]|\.ReadAllBytes|FromBase64String)`)
	for _, b := range blocks {
		if m := obsolete.FindString(b[1]); m != "" {
			t.Errorf("the compiled C# builds a certificate from bytes (%s), which PowerShell 7 refuses", strings.TrimSpace(m))
		}
	}
}
