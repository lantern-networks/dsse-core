package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type readinessTransport func(*http.Request) (*http.Response, error)

func (f readinessTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifyNoWaitRejectsAnAbsentDeployment(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "localhost,127.0.0.1", "Readiness test", 1, false); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "https://" + l.Addr().String()
	l.Close()
	started := time.Now()
	results := verifyDeployment(dir, url, []string{url}, url, "", nil, true)
	found := false
	for _, r := range results {
		if r.name == "the control plane answers" {
			found = !r.ok && !r.skipped && strings.Contains(r.note, "/healthz")
		}
	}
	if !found {
		t.Fatalf("absence was not a failed control-plane check: %+v", results)
	}
	// Exercise the entire orchestration too: it must not enter the separate fleet
	// startup wait after the first tier has already reported an absent authority.
	if err := runVerify(dir, url, url, url, "", "", "", true); err == nil || !strings.Contains(err.Error(), "check(s) failed") {
		t.Fatalf("expected a completed failed verdict, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("immediate verification took %s", elapsed)
	}
}

func TestImmediateReadinessStillProbesAndNeverAssumesSuccess(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		calls := 0
		client := &http.Client{Transport: readinessTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})}
		got, _, err := waitForTheControlPlaneToAnswer(client, "https://fixture.invalid", initialReadinessWait(120*time.Second, true))
		if err != nil || got != status || calls != 1 {
			t.Fatalf("status %d: got %d, %v, %d probes", status, got, err, calls)
		}
		waitForTheFleetViewToForm(client, "https://fixture.invalid", "", initialReadinessWait(90*time.Second, true))
		if calls != 2 {
			t.Fatalf("fleet readiness skipped its probe: %d calls", calls)
		}
	}
	for _, ready := range []bool{false, true} {
		calls := 0
		got := becomesTrueWithin(func() bool { calls++; return ready }, initialReadinessWait(90*time.Second, true))
		if got != ready || calls != 1 {
			t.Fatalf("Edge readiness %t: got %t, %d probes", ready, got, calls)
		}
	}
}

func TestNormalReadinessStillRetriesStartup(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: readinessTransport(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("starting")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	got, _, err := waitForTheControlPlaneToAnswer(client, "https://fixture.invalid", initialReadinessWait(120*time.Second, false))
	if err != nil || got != http.StatusOK || calls != 2 {
		t.Fatalf("normal startup stopped retrying: %d, %v, %d probes", got, err, calls)
	}
}
