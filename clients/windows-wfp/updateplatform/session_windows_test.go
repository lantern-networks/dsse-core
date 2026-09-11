//go:build windows

package updateplatform

import (
	"testing"
	"unsafe"
)

// TestWTSInfoExLayout pins the struct against the C definition by size.
//
// This is the failure this file most needs a guard for, because it is silent: a wrong array length or a
// missing pad does not error, it reads the later fields at the wrong offsets and returns a plausible idle
// time. The sizes are the documented WINSTATIONNAME_LENGTH (32), USERNAME_LENGTH (20) and DOMAIN_LENGTH (17)
// plus their terminators.
func TestWTSInfoExLayout(t *testing.T) {
	// 3 x 4-byte fields, then 72 UTF-16 code units, padded to the 8-byte alignment the LARGE_INTEGERs need,
	// then 5 x 8-byte times, then 6 x 4-byte counters.
	const wantLevel1 = 12 + (33+21+18)*2 + 4 + 5*8 + 6*4
	if got := unsafe.Sizeof(wtsInfoExLevel1{}); got != wantLevel1 {
		t.Fatalf("sizeof(WTSINFOEX_LEVEL1_W) = %d, want %d — every field after the name arrays is being read at the wrong offset", got, wantLevel1)
	}
	// Level (4) + pad (4) + the union.
	if got, want := unsafe.Sizeof(wtsInfoEx{}), uintptr(8+wantLevel1); got != want {
		t.Fatalf("sizeof(WTSINFOEXW) = %d, want %d", got, want)
	}
	if got := unsafe.Offsetof(wtsInfoEx{}.Data); got != 8 {
		t.Fatalf("WTSINFOEXW.Data at offset %d, want 8 (the union is 8-byte aligned)", got)
	}
}

// TestDescribeSessionsIsAnswerable runs the real query against this machine.
//
// It deliberately asserts almost nothing about the RESULT — that depends on who is logged in and whether the
// screen is locked, and a test that demanded a particular answer would fail on a build agent. What it does
// assert is that the call completes and produces a sentence, and it LOGS the reading so a human running
// `go test -v` on a real box can check it against what they can see: a user name that reads correctly is the
// evidence that the timestamps after it are being decoded from the right offsets.
func TestDescribeSessionsIsAnswerable(t *testing.T) {
	got := DescribeSessions()
	if got == "" {
		t.Fatal("DescribeSessions returned an empty string; an operator diagnosing a stalled rollout gets nothing")
	}
	t.Logf("this machine reports: %s", got)

	idle, idleKnown, inUse, inUseKnown := observeDevice()
	t.Logf("deviceInUse = %v (known=%v); deviceIdle = %v (known=%v)", inUse, inUseKnown, idle, idleKnown)

	// The one invariant that must hold regardless of machine state: an unknown must never be reported as a
	// duration, because the gate treats a known idle time as permission to update.
	if !idleKnown && idle != 0 {
		t.Fatalf("deviceIdle returned %v with known=false; an unknown must not carry a value", idle)
	}
}
