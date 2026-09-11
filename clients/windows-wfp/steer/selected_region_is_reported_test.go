package main

import (
	"strings"
	"testing"
)

// ★ The mistake this file exists for: a device sitting in the region that stayed up read as a flawless
// failover. The line has to say WHICH region, and it has to say that it is not the home one.
func TestANonHomeSelectionSaysSo(t *testing.T) {
	got := describeSelection("agents.tokyo.hikari.lab:443", "osaka")
	if !strings.Contains(got, "NOT the home region") || !strings.Contains(got, "osaka") || !strings.Contains(got, "tokyo") {
		t.Fatalf("a non-home selection has to name both and say which: %q", got)
	}
}

func TestTheHomeSelectionIsNamedToo(t *testing.T) {
	got := describeSelection("agents.osaka.hikari.lab:443", "osaka")
	if !strings.Contains(got, "HOME region") {
		t.Fatalf("got %q", got)
	}
}

// Home is matched case-insensitively: the profile's spelling and the endpoint's need not agree, and a
// case difference must not report a device as having left its home region.
func TestCaseDoesNotInventAFailover(t *testing.T) {
	got := describeSelection("agents.OSAKA.hikari.lab:443", "osaka")
	if strings.Contains(got, "NOT the home region") {
		t.Fatalf("a case difference was read as a region change: %q", got)
	}
}

// Nothing selected yet is its own answer, and must not read as "on the home region".
func TestNoSelectionIsNotTheHomeRegion(t *testing.T) {
	got := describeSelection("", "osaka")
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
