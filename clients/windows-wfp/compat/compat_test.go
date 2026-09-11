package compat

import (
	"strings"
	"testing"
)

func hasBlock(r Result, substr string) bool {
	for _, b := range r.Blocks {
		if strings.Contains(b, substr) {
			return true
		}
	}
	return false
}
func hasWarn(r Result, substr string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestEvaluate_CleanWin11Attestation_OK(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchAMD64, SecureBoot: true, WindowsBuild: 22631, DisplayVersion: "23H2"}, true)
	if !r.OK || len(r.Blocks) != 0 {
		t.Fatalf("clean attestation-signed install must pass: %+v", r)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("no warnings expected (Secure Boot ON is fine with attestation): %+v", r.Warnings)
	}
}

func TestEvaluate_ARM64_OK(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchARM64, SecureBoot: true, WindowsBuild: 26100}, true)
	if !r.OK {
		t.Fatalf("ARM64 native must be supported: %+v", r)
	}
}

func TestEvaluate_SMode_Blocks(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchAMD64, SMode: true, WindowsBuild: 22631}, true)
	if r.OK || !hasBlock(r, "S Mode") {
		t.Fatalf("S Mode must block: %+v", r)
	}
}

func TestEvaluate_X86_Blocks(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchX86, WindowsBuild: 22631}, true)
	if r.OK || !hasBlock(r, "x86") {
		t.Fatalf("x86 must block: %+v", r)
	}
}

func TestEvaluate_UnknownArch_Blocks(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchUnknown, WindowsBuild: 22631}, true)
	if r.OK || !hasBlock(r, "アーキテクチャ") {
		t.Fatalf("unknown arch must block: %+v", r)
	}
}

func TestEvaluate_TestSigned_SecureBoot_Blocks(t *testing.T) {
	// Test-signed driver on a machine with Secure Boot ON → driver won't load.
	r := Evaluate(Facts{Arch: ArchAMD64, SecureBoot: true, WindowsBuild: 22631}, false)
	if r.OK || !hasBlock(r, "Secure Boot") {
		t.Fatalf("test-signed + Secure Boot must block: %+v", r)
	}
}

func TestEvaluate_TestSigned_HVCI_Blocks(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchAMD64, HVCI: true, WindowsBuild: 22631}, false)
	if r.OK || !hasBlock(r, "HVCI") {
		t.Fatalf("test-signed + HVCI must block: %+v", r)
	}
}

func TestEvaluate_Attestation_HVCI_WarnsNotBlocks(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchAMD64, HVCI: true, SecureBoot: true, WindowsBuild: 24000}, true)
	if !r.OK {
		t.Fatalf("attestation-signed + HVCI must PASS (compliant driver): %+v", r)
	}
	if !hasWarn(r, "HVCI") {
		t.Fatalf("expected an HVCI compliance note: %+v", r.Warnings)
	}
}

func TestEvaluate_PreWin11_Warns(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchAMD64, WindowsBuild: 19045, DisplayVersion: "22H2"}, true)
	if !r.OK {
		t.Fatalf("pre-Win11 is a warning, not a block: %+v", r)
	}
	if !hasWarn(r, "Windows 11 未満") {
		t.Fatalf("expected a pre-Win11 warning: %+v", r.Warnings)
	}
}

func TestEvaluate_MultipleBlocks_Deduped_Sorted(t *testing.T) {
	r := Evaluate(Facts{Arch: ArchX86, SMode: true, SecureBoot: true, HVCI: true}, false)
	if r.OK {
		t.Fatalf("expected blocked")
	}
	// sorted + de-duplicated: no adjacent duplicates, stable order.
	for i := 1; i < len(r.Blocks); i++ {
		if r.Blocks[i] < r.Blocks[i-1] {
			t.Fatalf("blocks not sorted: %+v", r.Blocks)
		}
		if r.Blocks[i] == r.Blocks[i-1] {
			t.Fatalf("duplicate block: %q", r.Blocks[i])
		}
	}
	if !strings.Contains(r.Summary(), "BLOCKED") {
		t.Fatalf("summary should say BLOCKED: %q", r.Summary())
	}
}
