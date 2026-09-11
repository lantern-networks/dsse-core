//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// isAllDigits is the guard that decides whether a persisted NoActiveProbe snapshot is safe to splice back into
// the restore PowerShell as a literal -Value. Anything that is not a pure digit run must be rejected (treated
// as "absent" -> Remove), so a corrupted or hostile backup file can never inject a command. These cases pin
// that contract, including the injection-shaped inputs the guard exists to stop.
func TestIsAllDigits(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0", true},
		{"1", true},
		{"123", true},
		{"00", true},
		{"", false},
		{"absent", false},
		{" 1", false},  // leading space
		{"1 ", false},  // trailing space
		{"1a", false},  // trailing letter
		{"a1", false},  // leading letter
		{"-1", false},  // sign
		{"1.0", false}, // decimal point
		{"1,2", false}, // comma
		{"0x1", false}, // hex prefix
		{"１２３", false}, // full-width digits (not ASCII 0-9)
		// injection-shaped values that MUST be rejected so they are never written as -Value:
		{"1; Remove-Item C:\\ -Recurse", false},
		{"1`nStop-Service Foo", false},
		{"$(Get-Process)", false},
	}
	for _, c := range cases {
		if got := isAllDigits(c.in); got != c.want {
			t.Errorf("isAllDigits(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ncsiProbeBackupPath should sit next to the executable (so a clean stop / --mode recover after a service
// restart can still find the snapshot) and carry the expected filename.
func TestNCSIProbeBackupPath(t *testing.T) {
	p := ncsiProbeBackupPath()
	if p == "" {
		t.Fatal("ncsiProbeBackupPath returned empty")
	}
	if base := filepath.Base(p); base != "dsse_ncsi_probe_backup.txt" {
		t.Errorf("backup basename = %q, want dsse_ncsi_probe_backup.txt", base)
	}
	// It must be an absolute path next to the binary (not a bare relative filename) on the normal path where
	// os.Executable() succeeds — i.e. it should contain a directory separator.
	if !strings.ContainsRune(p, filepath.Separator) {
		t.Errorf("backup path %q has no directory component", p)
	}
}
