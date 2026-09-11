package edgeplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// markerTransport records that it was used and answers 200, so a test can assert WHICH path a request took
// rather than only that it succeeded.
type markerTransport struct {
	used  bool
	hosts []string
}

func (m *markerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.used = true
	m.hosts = append(m.hosts, req.URL.Hostname())
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func resolverFor(fronted map[string]bool, err error) ConnectorResolveFunc {
	return func(_ context.Context, _, destination, _ string) (model.ConnectorRegistration, bool, error) {
		if err != nil {
			return model.ConnectorRegistration{}, false, err
		}
		return model.ConnectorRegistration{}, fronted[destination], nil
	}
}

// A private app published behind a connector must reach it through the tunnel. Sending it to the broker means a
// separate process direct-dialing into internal address space, where the SSRF pre-flight refuses it — so the app
// becomes unreachable from a steered browser, which is the product's core promise.
func TestConnectorFrontedDestinationTunnelsAndNeverReachesTheBroker(t *testing.T) {
	connector, broker := &markerTransport{}, &markerTransport{}
	rt := NewConnectorOrBrokerRoundTripper(resolverFor(map[string]bool{"intranet.corp.example": true}, nil), "tenant_a", connector, broker)

	req, err := http.NewRequest(http.MethodGet, "https://intranet.corp.example/reports", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !connector.used {
		t.Error("a connector-fronted destination must egress through the connector tunnel")
	}
	if broker.used {
		t.Error("a connector-fronted destination must NOT be re-originated by the broker")
	}
}

// The public web must still get the real Chrome stack. A selector that quietly sent everything down the
// connector transport would restore reachability and destroy the fingerprint the broker exists to provide.
func TestPublicDestinationGoesToTheBroker(t *testing.T) {
	connector, broker := &markerTransport{}, &markerTransport{}
	rt := NewConnectorOrBrokerRoundTripper(resolverFor(map[string]bool{"intranet.corp.example": true}, nil), "tenant_a", connector, broker)

	req, err := http.NewRequest(http.MethodGet, "https://www.cloudflare.com/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !broker.used {
		t.Error("a public destination must be re-originated by the broker")
	}
	if connector.used {
		t.Error("a public destination must NOT be sent down the connector transport")
	}
}

// An unresolvable route layer must not become an accidental bypass. Matching ConnectorEgressDialContext, it is
// treated as "no connector" — the request goes to the broker, where the SSRF pre-flight still guards it, so an
// internal destination fails closed instead of being direct-dialed unchecked.
func TestResolverFailureFallsToTheBrokerWhereTheGuardStillApplies(t *testing.T) {
	connector, broker := &markerTransport{}, &markerTransport{}
	rt := NewConnectorOrBrokerRoundTripper(resolverFor(nil, errors.New("registry unavailable")), "tenant_a", connector, broker)

	req, err := http.NewRequest(http.MethodGet, "https://intranet.corp.example/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if connector.used {
		t.Error("a failed lookup must not be treated as 'fronted by a connector'")
	}
	if !broker.used {
		t.Error("a failed lookup must fall through to the broker, not drop the request")
	}
}

// Self-gating: a deployment that publishes no private apps configures no resolver, and must behave exactly as it
// did before the selector existed — every destination through the broker.
func TestNoResolverIsTheBrokerVerbatim(t *testing.T) {
	broker := &markerTransport{}
	if got := NewConnectorOrBrokerRoundTripper(nil, "tenant_a", &markerTransport{}, broker); got != http.RoundTripper(broker) {
		t.Error("with no resolver the selector must be the broker transport verbatim, not a wrapper")
	}
}

// The composition trap, pinned so nobody "simplifies" the selector back into it: ConnectorAwareProxyClient
// replaces a transport's DialContext and needs an *http.Transport. Handed the broker's custom RoundTripper it
// silently substitutes http.DefaultTransport — every origin would then be dialed with a bare Go fingerprint,
// which is exactly what the broker exists to prevent, with nothing logged.
func TestConnectorAwareProxyClientSilentlyDiscardsANonTransportRoundTripper(t *testing.T) {
	broker := &markerTransport{}
	base := &http.Client{Transport: broker}

	wrapped := ConnectorAwareProxyClient(base, resolverFor(nil, nil), nil, "tenant_a", "", nil, nil, nil)
	if wrapped.Transport == http.RoundTripper(broker) {
		t.Fatal("test premise is stale: the broker transport survived the wrap")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	resp, err := wrapped.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if broker.used {
		t.Fatal("premise stale: the request reached the broker transport")
	}
	// The request succeeded WITHOUT the broker — the silent substitution, demonstrated rather than asserted in
	// a comment. This is why the selector lives at RoundTripper level.
}

// A WebSocket to a connector-fronted app takes the connector transport, not the broker's raw tunnel. The two
// produce 101 responses by different mechanisms — the broker synthesises one over a hijacked connection, the
// connector path gets a real one from net/http — so this pins that the connector side is actually usable as a
// bidirectional stream rather than merely returning the right status code.
func TestWebSocketToAConnectorFrontedDestinationTunnelsAndStaysBidirectional(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		_ = buf.Flush()
		line, err := buf.ReadString('\n') // whatever the client sends, echo it back
		if err != nil {
			return
		}
		_, _ = buf.WriteString("echo:" + line)
		_ = buf.Flush()
	}))
	defer origin.Close()

	host := strings.Split(strings.TrimPrefix(origin.URL, "http://"), ":")[0]
	broker := &markerTransport{}
	rt := NewConnectorOrBrokerRoundTripper(resolverFor(map[string]bool{host: true}, nil), "tenant_a", &http.Transport{}, broker)

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/socket", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if broker.used {
		t.Error("a connector-fronted WebSocket must NOT be re-originated by the broker")
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	stream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("the 101 body must be writable — a read-only body is not a WebSocket tunnel")
	}
	if _, err := stream.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}
	got := make([]byte, 64)
	n, err := stream.Read(got)
	if err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if want := "echo:ping\n"; string(got[:n]) != want {
		t.Errorf("tunnel round-trip: got %q want %q", got[:n], want)
	}
}
