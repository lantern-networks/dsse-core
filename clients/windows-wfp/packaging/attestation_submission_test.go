package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func attestationSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("build-attestation-cab.ps1")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAttestationUsesOSSRoot(t *testing.T) {
	s := attestationSource(t)
	if !strings.Contains(s, "$here = $PSScriptRoot") || !strings.Contains(s, "Join-Path $here '..\\..\\..'") || strings.Contains(s, "Join-Path $here '..\\..\\..\\..\\..'") {
		t.Fatal("CAB defaults must resolve inside an exported OSS tree")
	}
	for _, name := range []string{"go.mod", "VERSION"} {
		if _, err := os.Stat(filepath.Join("..", "..", "..", name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAttestationSubmissionIncludesSymbolsAndCatalog(t *testing.T) {
	s := attestationSource(t)
	for _, want := range []string{"@($SysPath, $InfPath, $PdbPath)", "Test-Path $p -PathType Leaf", `"$stage\dsse-wfp.sys"`, `"$stage\dsse-wfp.inf"`, `"$stage\dsse-wfp.pdb"`, `"$stage\dsse-wfp.cat"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("submission missing %q", want)
		}
	}
	strip := strings.Index(s, "& $signtool remove /s $staged")
	cat := strings.Index(s, "& $inf2cat")
	pack := strings.Index(s, "& makecab.exe")
	if strip < 0 || cat <= strip || pack <= cat {
		t.Fatal("catalog must describe stripped staged payload before CAB construction")
	}
	if !strings.Contains(s, "throw 'Inf2Cat.exe not found") || !strings.Contains(s, "throw 'infverif.exe not found") {
		t.Fatal("missing validation tools must not produce a submission candidate")
	}
}

func TestAttestationPreparationNeverSubmitsOrLoadsDriver(t *testing.T) {
	s := attestationSource(t)
	s = s[strings.Index(s, "[CmdletBinding()]"):]
	for _, forbidden := range []string{"Invoke-WebRequest", "Invoke-RestMethod", "sc.exe start", "bcdedit", "pnputil"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("CAB preparation invokes %q", forbidden)
		}
	}
	if !strings.Contains(s, "if ($Backend -eq 'none')") || !strings.Contains(s, "if ((Test-Path $cabPath) -and -not $Force)") {
		t.Fatal("preserve dry-run and signed artifact overwrite protections")
	}
}

func TestAttestationScriptParsesWhenPowerShellIsAvailable(t *testing.T) {
	ps, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell parser requires the Windows/build host; no script execution")
	}
	p, err := filepath.Abs("build-attestation-cab.ps1")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:DSSE_ATTEST_PARSE_PATH,[ref]$t,[ref]$e);if($e.Count){$e | ForEach-Object {$_.ErrorId};exit 1}")
	cmd.Env = append(os.Environ(), "DSSE_ATTEST_PARSE_PATH="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PowerShell syntax: %v %s", err, out)
	}
}
