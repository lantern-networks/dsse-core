package tunnel

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★ THE FAILURE THIS PINS WAS "REGISTERED, AND UNREACHABLE FOR EVER" (2026-08-25). A connector given a URL
// with no port registered fine — Go's HTTP client defaults 443 for https — and then every tunnel dial failed
// with "missing port in address". The Site showed it enrolled and nothing behind it could be reached.
func TestDialTLSDefaultsThePortFromTheScheme(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented) // the upgrade is not the point; reaching the socket is
	}))
	defer srv.Close()

	// The guard: the old behaviour, reproduced. A portless host must NOT reach net.Dial unchanged.
	_, err := DialTLS(context.Background(), "wss://127.0.0.1", nil,
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server
	if err != nil && strings.Contains(err.Error(), "missing port in address") {
		t.Fatalf("a portless wss URL still reaches the dialer without a port: %v", err)
	}

	// And the ordinary case is untouched: an explicit port is used as given.
	if _, err := DialTLS(context.Background(), "wss://"+strings.TrimPrefix(srv.URL, "https://"), nil,
		&tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // test server
		t.Fatal("the handshake against a server that answers 501 was expected to fail at the upgrade")
	} else if strings.Contains(err.Error(), "missing port") {
		t.Fatalf("an explicit port was lost: %v", err)
	}
}
