//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

// The current process is owned by the logged-in user running the test, so resolving its PID must yield a
// non-empty account name (and PID 0 must fail-safe to "").
func TestResolveOSUserForPID(t *testing.T) {
	if got := osUserForPID(0); got != "" {
		t.Fatalf("osUserForPID(0) = %q, want empty (fail-safe)", got)
	}
	self := osUserForPID(uint32(os.Getpid()))
	if self == "" {
		t.Fatal("osUserForPID(self) is empty; expected the logged-in account")
	}
	// Account name is "DOMAIN\\user" or "user"; sanity-check the user segment is non-empty.
	user := self
	if i := strings.LastIndex(self, `\`); i >= 0 {
		user = self[i+1:]
	}
	if user == "" {
		t.Fatalf("resolved account %q has empty user segment", self)
	}
	t.Logf("self OS user = %q", self)
}

// Resolving the current process's PID must yield its executable base name (the test binary, "*.exe"), and PID 0
// must fail-safe to "".
func TestResolveOSAppForPID(t *testing.T) {
	if got := osAppForPID(0); got != "" {
		t.Fatalf("osAppForPID(0) = %q, want empty (fail-safe)", got)
	}
	app := osAppForPID(uint32(os.Getpid()))
	if app == "" {
		t.Fatal("osAppForPID(self) is empty; expected the executable base name")
	}
	if !strings.HasSuffix(strings.ToLower(app), ".exe") {
		t.Fatalf("osAppForPID(self) = %q, expected an .exe base name", app)
	}
	if strings.ContainsAny(app, `\/ `) {
		t.Fatalf("osAppForPID(self) = %q must be a bare base name (no path/space)", app)
	}
	t.Logf("self app = %q", app)
}
