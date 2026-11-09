package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A service started with no update-signing key waits before its first pass, so the start the installer makes
// moments before it hands the keys over does not refuse (2026-11-06: a fresh install showed "refusing the
// update" on the Devices screen for a device that had its keys five seconds later).
func TestAKeylessStartWaitsBeforeItsFirstPass(t *testing.T) {
	if got := firstPassDelay(0); got < time.Minute {
		t.Fatalf("a keyless start waits %s; the installer's restart with keys comes seconds later and must win", got)
	}
	if got := firstPassDelay(1); got != 0 {
		t.Fatalf("a service holding a key waits %s before its first pass; it should start at once", got)
	}
}

func TestTheServiceWaitsBeforeTheFirstPassOnlyWhenKeyless(t *testing.T) {
	src, err := os.ReadFile("main_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	wait := strings.Index(body, "if wait := firstPassDelay(s.u.trustedKeyCount()); wait > 0 {")
	first := strings.Index(body, "\ttick(s.u, evt, thr)\n\t// ★★ A REFUSAL STILL STANDING AT START")
	if wait < 0 || first < 0 || wait > first {
		t.Fatal("the service no longer waits before its first pass when it holds no key")
	}
}
