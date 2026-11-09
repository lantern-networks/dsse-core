package main

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ★ The mistake this file exists for: a device sitting in the region that stayed up read as a flawless
// failover. The line has to say WHICH region, and it has to say that it is not the home one.
func TestANonHomeSelectionSaysSo(t *testing.T) {
	got := describeSelection("agents.tokyo.hikari.lab:443", "", "osaka")
	if !strings.Contains(got, "NOT the home region") || !strings.Contains(got, "osaka") || !strings.Contains(got, "tokyo") {
		t.Fatalf("a non-home selection has to name both and say which: %q", got)
	}
}

func TestTheHomeSelectionIsNamedToo(t *testing.T) {
	got := describeSelection("agents.osaka.hikari.lab:443", "", "osaka")
	if !strings.Contains(got, "HOME region") {
		t.Fatalf("got %q", got)
	}
}

// Home is matched case-insensitively: the profile's spelling and the endpoint's need not agree, and a
// case difference must not report a device as having left its home region.
func TestCaseDoesNotInventAFailover(t *testing.T) {
	got := describeSelection("agents.OSAKA.hikari.lab:443", "", "osaka")
	if strings.Contains(got, "NOT the home region") {
		t.Fatalf("a case difference was read as a region change: %q", got)
	}
}

// Nothing selected yet is its own answer, and must not read as "on the home region".
func TestNoSelectionIsNotTheHomeRegion(t *testing.T) {
	got := describeSelection("", "", "osaka")
	if strings.Contains(got, "HOME region") {
		t.Fatalf("an empty endpoint read as a selection: %q", got)
	}
}

// The refusal path names the resolvers, because "could not resolve" alone is not actionable -- and the
// loopback proxy is deliberately never among them (that is the cycle out-of-band resolution breaks).
func TestTheResolversTriedAreNamed(t *testing.T) {
	if got := describeUpstreams([]string{"127.0.0.1", "::1"}); !strings.Contains(got, "none from this box") {
		t.Fatalf("a loopback-only upstream list must report as none: %q", got)
	}
	if got := describeUpstreams([]string{"192.0.2.1", "127.0.0.1"}); !strings.Contains(got, "192.0.2.1") || strings.Contains(got, "127.0.0.1") {
		t.Fatalf("got %q", got)
	}
}

// Acceptance C (2026-11-07): in one region with three nodes the entrances are agents.node-X.<deployment>, so
// the host never contains the region's name. The region the endpoint list names decides.
func TestAThreeNodeEntranceOnTheHomeRegionIsHome(t *testing.T) {
	got := describeSelection("agents.node-a.c.lab041.test:443", "region-a", "region-a")
	if !strings.Contains(got, "the HOME region") || strings.Contains(got, "NOT") {
		t.Fatalf("a home-region entrance named by node was called not home: %s", got)
	}
	got = describeSelection("agents.region-a.example.test:443", "region-b", "region-a")
	if !strings.Contains(got, "NOT the home region") {
		t.Fatalf("a listed region other than home was called home because the host contained its name: %s", got)
	}
}

// Review R1 (2026-11-08): the bootstrap endpoint is stored with a host and no region before the list chooses.
// The report waits for the list's choice instead of judging the bootstrap host by its name, and then says
// HOME for a home selection.
func TestTheReportWaitsForTheListsChoiceAndThenSaysHome(t *testing.T) {
	var active atomic.Pointer[activeEndpoint]
	active.Store(&activeEndpoint{host: "agents.node-a.c.lab041.test:443", serverName: "agents.node-a.c.lab041.test"})
	tc := transportConfig{active: &active}
	out := captureStdout(t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			time.Sleep(1500 * time.Millisecond) // the list's selection lands after the first tick
			active.Store(&activeEndpoint{host: "agents.node-a.c.lab041.test:443", serverName: "agents.node-a.c.lab041.test",
				dialAddrs: []string{"203.0.113.10:443"}, region: "region-a"})
		}()
		reportSelectedRegion(ctx, tc, "region-a")
	})
	if strings.Contains(out, "NOT the home region") {
		t.Fatalf("the bootstrap endpoint was reported as a non-home selection before the list chose: %s", out)
	}
	if !strings.Contains(out, "the HOME region") {
		t.Fatalf("the list's home selection was never reported: %s", out)
	}
}

// captureStdout runs fn with os.Stdout sent to a pipe and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = saved
	_ = w.Close()
	return <-done
}
