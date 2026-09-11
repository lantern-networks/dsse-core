//go:build windows

package main

import (
	"strings"
	"testing"
	"time"
)

// ★★★ THE REGRESSION THIS PINS (2026-09-01, measured on win-dev-1): runBoundedOutput called c.Start() and
// then c.Output(), and Output starts the command itself — so on a real box every call returned
// "exec: already started" and read NOTHING. vmEgressCreators could not enumerate, VM-egress was never applied,
// and the whole feature was inert while printing that it was active. The unit tests at the time exercised the
// DECISION (vmEgressFromProfile), never this exec path, so they stayed green.
//
// This test runs a real interpreter and asserts the OUTPUT comes back. Under the double-start bug it fails
// with "exec: already started"; under the fix it returns the echoed token.
func TestRunBoundedOutputActuallyReturnsOutput(t *testing.T) {
	cmd, err := hiddenPowerShell("Write-Output DSSE_BOUNDED_OK")
	if err != nil {
		t.Fatalf("hiddenPowerShell: %v", err)
	}
	out, err := runBoundedOutput(cmd, 20*time.Second)
	if err != nil {
		t.Fatalf("runBoundedOutput returned an error (the double-start bug returns \"exec: already started\" here): %v", err)
	}
	if !strings.Contains(out, "DSSE_BOUNDED_OK") {
		t.Fatalf("output did not come back — got %q. A function whose ANSWER is the point that returns no answer is the bug.", out)
	}
}

// The timeout leg must still return an error rather than hang, and must not leave the Wait goroutine blocked.
func TestRunBoundedOutputHonoursTheDeadline(t *testing.T) {
	cmd, err := hiddenPowerShell("Start-Sleep -Seconds 30")
	if err != nil {
		t.Fatalf("hiddenPowerShell: %v", err)
	}
	start := time.Now()
	_, err = runBoundedOutput(cmd, 2*time.Second)
	if err == nil {
		t.Fatal("a command that outlives the deadline should return an error")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("the deadline was not honoured: took %s", time.Since(start))
	}
}
