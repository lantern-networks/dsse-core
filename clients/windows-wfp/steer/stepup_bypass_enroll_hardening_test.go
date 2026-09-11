//go:build windows

package main

import "testing"

// TestValidatedStepUpURL pins fail-open review finding #29 (step-up URL): only a well-formed http/https URL with
// no command-line-breaking characters is accepted; anything else is refused so it is never launched.
func TestValidatedStepUpURL(t *testing.T) {
	good := []string{
		"https://console.local/?activate=ABC123",
		"http://10.0.0.5:8088/step-up",
	}
	for _, u := range good {
		if got, ok := validatedStepUpURL(u); !ok || got != u {
			t.Fatalf("valid URL %q rejected (ok=%v got=%q)", u, ok, got)
		}
	}
	bad := []string{
		"",
		`https://x/" --evil "y`,                // quote/space -> arg injection
		"file:///C:/Windows/System32/calc.exe", // non-web scheme -> arbitrary handler
		"javascript:alert(1)",                  // script scheme
		"calc.exe",                             // not a URL / no scheme
		"https://",                             // no host
		"https://host/\tpath",                  // control char
		"ftp://host/x",                         // disallowed scheme
	}
	for _, u := range bad {
		if _, ok := validatedStepUpURL(u); ok {
			t.Fatalf("unsafe portal URL %q must be refused", u)
		}
	}
}

// TestBypassCacheInvalidatedOnPortRecycle pins fail-open review finding #29 (stale bypass cache): a cached
// bypass=true for an excluded process must NOT be returned once its ephemeral port is recycled by a DIFFERENT
// (non-excluded) process — otherwise the new flow passes through unsteered.
func TestBypassCacheInvalidatedOnPortRecycle(t *testing.T) {
	b := newAppBypass([]string{"excluded.exe"})
	const port = uint16(50000)
	const excludedPID, otherPID = uint32(111), uint32(222)

	// Seed the resolver: port owned by the excluded process, decision cached bypass=true.
	b.owners = map[uint16]uint32{port: excludedPID}
	b.pidDecision = map[uint32]bool{excludedPID: true, otherPID: false}
	if bypass, _ := b.bypassReason(port); !bypass {
		t.Fatal("precondition: excluded process must be bypassed")
	}
	if d, ok := b.portDecision[port]; !ok || d.pid != excludedPID || !d.excluded {
		t.Fatalf("decision must be cached for the excluded pid, got %+v ok=%v", d, ok)
	}

	// Recycle: the SAME port number is now owned by a DIFFERENT, non-excluded process.
	b.owners = map[uint16]uint32{port: otherPID}
	bypass, _ := b.bypassReason(port)
	if bypass {
		t.Fatal("a recycled port owned by a non-excluded process must NOT return the stale bypass=true (fail-open #29)")
	}
	if d := b.portDecision[port]; d.pid != otherPID {
		t.Fatalf("cache must be re-keyed to the new owner pid, got %+v", d)
	}
}

// TestRunEnrollRequiresPinOrCA pins fail-open review finding #29 (enroll pin): enrollment must refuse to run over
// an unpinned transport (neither a CA pin nor a trusted enroll CA).
func TestRunEnrollRequiresPinOrCA(t *testing.T) {
	err := runEnroll("https://cp.example/enroll", "dev-1", "acme", "token", "tok", "", "", t.TempDir())
	if err == nil {
		t.Fatal("enrollment with neither --enroll-ca-pin nor --enroll-ca must be refused (unpinned bootstrap)")
	}
}
