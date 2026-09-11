//go:build !embedbroker

// These exercise the SIDECAR transport (an HTTP client against a test server standing in for the broker).
// The embedded build has no such client; its equivalent is transport_embedded_test.go, which drives the real
// engine instead.

package egressbroker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/swg"
)

// The broker is a REQUIRED component: with the in-process fallback engine deleted, an unset EGRESS_BROKER_URL
// leaves the decrypt-all path with no transport at all. Constructing must fail so the caller refuses to start,
// rather than every flow discovering it per-request.
func TestBrokerEgressRefusesToConstructWithoutBrokerURL(t *testing.T) {
	t.Setenv("EGRESS_BROKER_URL", "")
	rt, err := NewRoundTripper()
	if err == nil {
		t.Fatal("expected construction to FAIL with no broker configured")
	}
	if rt != nil {
		t.Error("expected no RoundTripper when construction fails")
	}
	if !strings.Contains(err.Error(), "EGRESS_BROKER_URL") {
		t.Errorf("error must name the missing setting, got %q", err)
	}
}

// A broker failure must surface as an upstream failure. The deleted fallback used to complete the flow over the
// fingerprint bot management already rejects, which hid the condition that should fail the node instead.
func TestBrokerEgressDoesNotFallBackOnBrokerFailure(t *testing.T) {
	// A listener that is closed immediately gives us an address nothing answers on.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	t.Setenv("EGRESS_BROKER_URL", deadURL)
	rt, err := NewRoundTripper()
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err == nil {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("expected the broker failure to be returned, not absorbed by a fallback")
	}
}

// The dial happens inside the broker process, so the Edge's dialer-level SSRF guards cannot see this egress. The
// pre-flight check in RoundTrip is the only thing standing between a decrypt-all flow and internal infrastructure.
func TestBrokerEgressBlocksInternalDestinations(t *testing.T) {
	// The broker must never be contacted for a blocked destination, so point at a server that fails the test if it is.
	var contacted bool
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		contacted = true
		w.WriteHeader(http.StatusOK)
	}))
	defer broker.Close()

	t.Setenv("EGRESS_BROKER_URL", broker.URL)
	rt, err := NewRoundTripper()
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	swg.SetInternalBlockEnabled(true)
	defer swg.SetInternalBlockEnabled(false)

	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err == nil {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("expected cloud-metadata egress to be BLOCKED")
	}
	if !strings.Contains(err.Error(), "ssrf egress guard") {
		t.Errorf("expected the SSRF guard to be the refusal reason, got %q", err)
	}
	if contacted {
		t.Error("the broker was contacted for a blocked destination — the guard must run BEFORE re-origination")
	}
}

// A broker restart leaves a window where the name does not resolve or the port refuses. Twice on 2026-08-04 a
// live flow was lost to exactly that window, and with no fallback engine a lost flow is a failed page. The retry
// must bridge it — on the same engine, never by switching to another one.
func TestBrokerEgressRetriesAcrossARestartWindow(t *testing.T) {
	swg.SetInternalBlockEnabled(false)

	// Bind a port, then close it: dials refuse until we put a server back on the same address.
	probe := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(probe.URL, "http://")
	probe.Close()

	t.Setenv("EGRESS_BROKER_URL", "http://"+addr)
	rt, err := NewRoundTripper()
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	// Bring the "broker" back mid-flight, the way a container recreate does.
	served := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})}
		close(served)
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
	}()

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	select {
	case <-served:
	default:
		t.Fatal("test did not exercise a restart: the replacement listener never came up")
	}
	if err != nil {
		t.Fatalf("expected the retry to bridge the restart window, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after the broker returned, got %d", resp.StatusCode)
	}
}

// Retrying an upload would re-send a POST the user made once. A body that has already been streamed cannot be
// replayed, so such a request must fail on the first connection error instead.
func TestBrokerEgressDoesNotRetryRequestsWithABody(t *testing.T) {
	swg.SetInternalBlockEnabled(false)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	t.Setenv("EGRESS_BROKER_URL", deadURL)
	rt, err := NewRoundTripper()
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.com/upload", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	start := time.Now()
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("expected the request to fail")
	}
	// The full backoff ladder is ~2s; a bodied request must not wait it out.
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Errorf("bodied request appears to have been retried (took %v)", elapsed)
	}
}

// An error the broker ANSWERED with is a real result. Re-attempting it would double every origin-side failure.
func TestBrokerEgressDoesNotRetryAnsweredRequests(t *testing.T) {
	swg.SetInternalBlockEnabled(false)
	var calls int
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer broker.Close()

	t.Setenv("EGRESS_BROKER_URL", broker.URL)
	rt, err := NewRoundTripper()
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("a relayed 502 is a response, not a transport error: %v", err)
	}
	defer resp.Body.Close()
	if calls != 1 {
		t.Errorf("expected exactly 1 call to the broker, got %d", calls)
	}
}
