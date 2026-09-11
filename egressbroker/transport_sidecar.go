//go:build !embedbroker

// Sidecar transport: the engine runs as a separate service and the edge speaks HTTP to it. This is the default
// build. The unified alternative is transport_embedded.go, selected with -tags embedbroker.

package egressbroker

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/swg"
)

// EngineEmbedded reports whether the egress engine runs inside this process. False here: the engine is a
// separate service, so its liveness is a real question and readiness is right to depend on it.
const EngineEmbedded = false

// The broker is a REQUIRED component, not an opt-in accelerator, and there is deliberately no in-process fallback
// engine. A Go TLS/H2 emulation is the fingerprint bot management already rejects, and bot management fronts a
// large share of the ordinary web rather than a short list of hostile origins — so falling back to one does not
// deliver working traffic. It converts one legible failure ("the broker is down") into scattered origin-dependent
// breakage, and in a clustered deployment it hides the very condition that should drain the node. Broker errors
// therefore surface as upstream failures (the edge 502s), and an unconfigured broker refuses to construct rather
// than degrading silently.
type roundTripper struct {
	brokerURL string
	client    *http.Client // h2c full-duplex client to the broker (WS needs concurrent request/response streaming)
}

// NewRoundTripper builds the egress transport from EGRESS_BROKER_URL. It returns an error when that is unset:
// with no fallback engine, an unconfigured broker means the browser-mimic path has no transport at all, and the
// caller must refuse to start rather than serve every flow into a per-request failure.
func NewRoundTripper() (http.RoundTripper, error) {
	brokerURL, err := URLFromEnv()
	if err != nil {
		return nil, err
	}
	// EGRESS_BROKER_HOSTS/EGRESS_BROKER_ALL used to choose between the broker and the in-process fallback per host.
	// With the fallback deleted the broker is the only engine, so host scoping no longer selects anything — say so
	// rather than letting a stale setting imply traffic is being scoped.
	if h := strings.TrimSpace(os.Getenv("EGRESS_BROKER_HOSTS")); h != "" {
		log.Printf("swg egress: EGRESS_BROKER_HOSTS=%q is IGNORED — the broker is the only egress engine, so all decrypt-all egress re-originates through it", h)
	}
	return NewRoundTripperForURL(brokerURL)
}

// NewRoundTripperForURL builds the egress transport for an explicitly supplied broker URL — the form a
// flag-configured edge uses. NewRoundTripper is the environment-driven wrapper around it, so both entry points
// produce a transport with identical pooling and redirect behaviour.
func NewRoundTripperForURL(brokerURL string) (http.RoundTripper, error) {
	brokerURL = strings.TrimRight(strings.TrimSpace(brokerURL), "/")
	if brokerURL == "" {
		return nil, errors.New("egress broker URL is empty: the broker is a required component (no in-process fallback engine exists)")
	}
	// Pooled HTTP/1.1 transport for the HTTP re-origination path (the WS path uses its own raw hijacked dial). An
	// HTTP/2 client coalesced ALL egress onto ONE h2c connection to the broker, whose single-connection flow control
	// throttled heavy pages (a deep scroll's image storm) -> the browser cancelled slow requests -> dropped images.
	// HTTP/1.1 lets Go pool MANY parallel connections to the broker.
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 512, // the broker is a single host — allow many warm parallel connections
		MaxConnsPerHost:     0,   // unlimited concurrent connections
		IdleConnTimeout:     90 * time.Second,
	}
	log.Printf("swg egress: browser-faithful BROKER enabled (url=%s) — curl-impersonate is the ONLY egress engine; broker failure fails the flow, it does not fall back", brokerURL)
	// A RoundTripper must NOT follow redirects — it returns the origin's response (30x included) verbatim so the
	// Edge relays it to the browser, which follows it. Without this the h2c client chased OAuth redirects itself
	// (auth.copilot.microsoft.com -> accounts.google.com …), breaking sign-in and the whole Copilot flow.
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &roundTripper{brokerURL: brokerURL, client: client}, nil
}

// RoundTrip re-originates every request through the broker. A broker failure is returned to the caller (the Edge
// turns it into a 502) — the flow fails legibly instead of completing over a detectable fingerprint.
func (b *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// SSRF guard. The dial happens inside the broker process, so the Edge's dialer-level guards (swg.EgressControl
	// on the Control hook, swg.GuardDialContext post-connect) cannot see this egress at all — this pre-flight check
	// is what keeps the decrypt-all path from being an open pivot into internal/metadata addresses.
	if err := swg.CheckEgressDestination(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	if IsWSUpgrade(req) {
		return b.roundTripWS(req)
	}
	return b.roundTripHTTP(req)
}

func (b *roundTripper) reorigHeaders(dst http.Header, src http.Header) {
	for _, line := range reorigHeaderLines(src) {
		dst.Add("X-Reorig-Header", line)
	}
}

// brokerRestartBackoff bridges a broker restart. A container recreate leaves a window of a few seconds in which
// the broker's name does not resolve or the port refuses — measured twice on 2026-08-04, and each time a live
// flow was lost to it. With no fallback engine, "lost" means a failed page rather than a degraded one, so a
// connection-level failure is worth a bounded wait on the SAME engine. This is not the deleted fallback in
// another form: it never changes engine, and it gives up loudly instead of silently succeeding over a
// fingerprint the origin rejects.
var brokerRestartBackoff = []time.Duration{200 * time.Millisecond, 600 * time.Millisecond, 1200 * time.Millisecond}

// roundTripHTTP forwards the decided request to broker /v1/reoriginate; the broker's response IS the origin response
// (status/headers/body relayed), so we return it directly.
func (b *roundTripper) roundTripHTTP(req *http.Request) (*http.Response, error) {
	attempts := 1
	if b.retriableRequest(req) {
		attempts += len(brokerRestartBackoff)
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return nil, fmt.Errorf("broker reoriginate: %w", req.Context().Err())
			case <-time.After(brokerRestartBackoff[attempt-1]):
			}
			log.Printf("swg egress: broker unreachable for %s (%v) — retry %d/%d", req.URL.Hostname(), lastErr, attempt, len(brokerRestartBackoff))
		}
		breq, err := http.NewRequestWithContext(req.Context(), http.MethodPost, b.brokerURL+"/v1/reoriginate", req.Body)
		if err != nil {
			return nil, err
		}
		breq.Header.Set("X-Reorig-Method", req.Method)
		breq.Header.Set("X-Reorig-URL", req.URL.String())
		b.reorigHeaders(breq.Header, req.Header)
		resp, err := b.client.Do(breq)
		if err == nil {
			resp.Request = req
			return resp, nil
		}
		lastErr = err
		// Only a failure to REACH the broker is retriable. Anything the broker answered — including an origin
		// error it relayed — is a real result and must not be re-attempted.
		if !isBrokerUnreachable(err) {
			break
		}
	}
	return nil, fmt.Errorf("broker reoriginate: %w", lastErr)
}

// retriableRequest reports whether re-sending req is safe. A request whose body has already been streamed cannot
// be replayed, and replaying an upload — a POST the user made once — is a worse outcome than failing it. Only
// bodyless requests qualify, which is the shape of the page loads a restart window actually interrupts.
func (b *roundTripper) retriableRequest(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody
}

// isBrokerUnreachable distinguishes "the broker is not there right now" (restart window: DNS has no entry yet, or
// the port refuses) from every other failure. Matched on the wrapped syscall/DNS errors rather than on strings,
// so a message change upstream cannot silently turn retries off.
func isBrokerUnreachable(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	var opErr *net.OpError
	// A dial that failed for any other reason (the broker mid-start, the bridge reconfiguring) is still a
	// failure to reach it — but a read/write error means bytes were already exchanged, so it is not.
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// roundTripWS opens broker /v1/ws over a RAW h1 connection the broker hijacks, then presents that connection as a
// 101 response whose Body is the tunnel (Write = client->origin, Read = origin->client). A raw byte tunnel avoids
// Go's h2 client not streaming a request body full-duplex (which zeroed the client->origin direction).
func (b *roundTripper) roundTripWS(req *http.Request) (*http.Response, error) {
	hostPort := strings.TrimPrefix(strings.TrimPrefix(b.brokerURL, "http://"), "https://")
	conn, err := net.DialTimeout("tcp", hostPort, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("broker ws dial: %w", err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST /v1/ws HTTP/1.1\r\nHost: %s\r\n", hostPort)
	fmt.Fprintf(&sb, "X-Reorig-URL: %s\r\n", req.URL.String())
	for name, vals := range req.Header {
		for _, v := range vals {
			fmt.Fprintf(&sb, "X-Reorig-Header: %s: %s\r\n", name, v)
		}
	}
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker ws write: %w", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker ws ack: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("broker ws: %s", strings.TrimSpace(statusLine))
	}
	for { // drain the ack headers up to the blank line
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("broker ws ack headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}},
		Body:    &brokerRawConn{conn: conn, r: br},
		Request: req,
	}, nil
}

// brokerRawConn is the raw hijacked tunnel to the broker as an io.ReadWriteCloser (Read buffers early bytes).
type brokerRawConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func (c *brokerRawConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *brokerRawConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *brokerRawConn) Close() error                { return c.conn.Close() }
