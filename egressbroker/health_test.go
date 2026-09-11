package egressbroker

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBrokerHealthMonitorNilAndUnknownAreReady(t *testing.T) {
	var nilMonitor *HealthMonitor
	if ready, _ := nilMonitor.Ready(); !ready {
		t.Fatal("nil monitor (no broker configured) must be ready")
	}
	m := NewHealthMonitor("http://broker.invalid", 0, nil)
	if ready, _ := m.Ready(); !ready {
		t.Fatal("a monitor that has not probed yet must be ready — start-up must not look like an outage")
	}
}

func TestBrokerHealthMonitorUnusableNeedsConsecutiveFailures(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("probe path = %q, want /healthz", r.URL.Path)
		}
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var logs []string
	m := NewHealthMonitor(server.URL, 0, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})

	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("healthy probe must be ready")
	}

	// A blip below the threshold must not flip readiness (a broker restart window is a few seconds and the
	// request path already bridges it) and must log nothing.
	healthy.Store(false)
	m.Check()
	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("2 consecutive failures is below the unusable threshold; must still be ready")
	}
	healthy.Store(true)
	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("recovered blip must be ready")
	}
	if len(logs) != 0 {
		t.Fatalf("a below-threshold blip must not log transitions, got %v", logs)
	}

	// Threshold reached: unready, with the reason, logged exactly once.
	healthy.Store(false)
	for i := 0; i < brokerUnusableConsecutiveFailures; i++ {
		m.Check()
	}
	ready, reason := m.Ready()
	if ready {
		t.Fatalf("%d consecutive failures must be unready", brokerUnusableConsecutiveFailures)
	}
	if !strings.Contains(reason, "consecutive probe failures") {
		t.Fatalf("unready reason %q must say why", reason)
	}
	m.Check() // stays unusable: must not log again
	if got := countContaining(logs, "UNUSABLE"); got != 1 {
		t.Fatalf("UNUSABLE must be logged exactly once at the transition, got %d in %v", got, logs)
	}

	// Recovery: ready again, logged once.
	healthy.Store(true)
	m.Check()
	if ready, _ := m.Ready(); !ready {
		t.Fatal("recovered broker must be ready")
	}
	if got := countContaining(logs, "RECOVERED"); got != 1 {
		t.Fatalf("RECOVERED must be logged exactly once, got %d in %v", got, logs)
	}
}

func TestBrokerHealthMonitorUnreachableBrokerCountsAsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // closed immediately: connection refused
	m := NewHealthMonitor(server.URL, 0, nil)
	for i := 0; i < brokerUnusableConsecutiveFailures; i++ {
		m.Check()
	}
	if ready, _ := m.Ready(); ready {
		t.Fatal("an unreachable broker must count toward unusable, not only HTTP errors")
	}
}

func countContaining(logs []string, needle string) int {
	n := 0
	for _, l := range logs {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}
