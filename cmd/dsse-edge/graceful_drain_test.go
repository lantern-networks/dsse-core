package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// Phase 4 graceful drain: once the drain flag is set (on SIGTERM), /healthz reports 503 so the L4/L7 LB stops
// sending NEW connections here while in-flight requests bleed out — the basis of a zero-outage rolling
// upgrade. A nil/unset drain state keeps /healthz at 200.
func TestHealthzReportsDrainingWhenDrainStateSet(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	drain := &atomic.Bool{}
	h := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		Registry:   connector.NewRegistry(),
		AdminAuth:  newAdminAuthStore(),
		DrainState: drain,
	})
	get := func() int {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := get(); code != http.StatusOK {
		t.Fatalf("a healthy edge must serve /healthz 200, got %d", code)
	}
	drain.Store(true)
	if code := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("a draining edge must serve /healthz 503 (so the LB drains it), got %d", code)
	}
	drain.Store(false)
	if code := get(); code != http.StatusOK {
		t.Fatalf("/healthz must return to 200 when not draining, got %d", code)
	}
}

// A graceful Shutdown surfaces http.ErrServerClosed; the listener treats it as success (a clean drain), not a
// startup failure.
func TestIgnoreServerClosed(t *testing.T) {
	if err := ignoreServerClosed(http.ErrServerClosed); err != nil {
		t.Fatalf("ErrServerClosed must be treated as success, got %v", err)
	}
	real := http.ErrHandlerTimeout
	if err := ignoreServerClosed(real); err != real {
		t.Fatalf("a real error must pass through, got %v", err)
	}
}
