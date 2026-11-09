package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Found 2026-11-07 on the 0.4.1 acceptance B rerun: the verify script's report carried a stray line,
// "System.Threading.Tasks.VoidTaskResult". An async method's Task is a Task<VoidTaskResult> underneath, so a bare
// GetAwaiter().GetResult() statement returns that object and PowerShell prints it. Every such statement must
// discard what it returns.
func TestNoAwaitedTaskIsLeftToPrintItsResult(t *testing.T) {
	raw, err := os.ReadFile("verify-windows-install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`^\s*\$[A-Za-z_]+\.GetAwaiter\(\)\.GetResult\(\)\s*$`)
	for i, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if bare.MatchString(line) {
			t.Errorf("line %d prints the awaited task's result into the report: %s", i+1, strings.TrimSpace(line))
		}
	}
}
