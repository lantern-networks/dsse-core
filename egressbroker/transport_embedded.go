//go:build embedbroker

// Embedded transport: the engine runs INSIDE this process. Selected with -tags embedbroker; the default build
// is the sidecar in transport_sidecar.go. This variant requires cgo and libcurl-impersonate, so it only builds
// where the engine library does — the same places the standalone broker binary builds.
//
// What it removes, relative to speaking HTTP to a sidecar: the per-request marshalling of an already-decided
// request into X-Reorig-* headers and back, the full in-memory buffering of every upload body on the far side,
// a TCP hop for every decrypted byte in each direction, and the restart window in which the sidecar's name does
// not resolve. What it does NOT remove is the engine's own nature — it is still cgo, and it is still the same
// code, imported rather than copied.

package egressbroker

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/egress-broker/engine"
	"github.com/lantern-networks/dsse-core/swg"
)

// EngineEmbedded reports whether the egress engine runs inside this process. True here — which makes probing
// a broker over the network meaningless. There is nothing to probe, and a deployment that has dropped the
// sidecar (the point of embedding) would otherwise flip this node to UNREADY while its egress works perfectly.
// A readiness gate that reports a failure the node does not have is worse than having no gate.
const EngineEmbedded = true

type roundTripper struct{}

// NewRoundTripper builds the in-process egress transport. EGRESS_BROKER_URL is still read and still required:
// the edge and the broker are one unit, so a deployment that has not been told it has an egress engine is
// misconfigured whether or not that engine happens to be linked in. Keeping the requirement identical across
// both builds also means a deployment can move between them without a config change.
func NewRoundTripper() (http.RoundTripper, error) {
	if _, err := URLFromEnv(); err != nil {
		return nil, err
	}
	return NewRoundTripperForURL("embedded")
}

// NewRoundTripperForURL ignores the URL — there is no separate service to address — but keeps the signature so
// the composition root is identical in both builds.
func NewRoundTripperForURL(string) (http.RoundTripper, error) {
	installPeerGuard()
	log.Printf("swg egress: browser-faithful engine EMBEDDED in this process (curl-impersonate, profile=%s) — no broker sidecar, no per-request hop", engine.ImpersonateBinary())
	return &roundTripper{}, nil
}

// installPeerGuard wires the product's egress block list into the engine, so every connection it makes is
// checked at the moment its peer address is known. This is what brings the re-origination path up to the
// standard every other egress path already meets: swg.GuardDialContext checks the CONNECTED peer, while a
// destination pre-flight can only check a name that gets resolved a second time before it is dialled.
//
// The pre-flight in RoundTrip stays. It refuses an obviously-internal destination without spending a
// connection, and two checks that disagree is not a risk here — they enforce the same list.
var installPeerGuard = sync.OnceFunc(func() {
	engine.SetPeerGuard(func(ip string) error {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("ssrf egress guard: peer address %q is not an IP", ip)
		}
		if swg.IsBlockedEgressIP(parsed) {
			return fmt.Errorf("ssrf egress guard: connected peer %s is internal/link-local/loopback/metadata", parsed)
		}
		return nil
	})
})

// RoundTrip re-originates the decided request through the in-process engine.
func (b *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// SSRF guard. Unlike the sidecar build this could now check the CONNECTED peer rather than a resolved
	// hostname, closing the TOCTOU the split forces — but that is a behaviour change and belongs in its own
	// commit, so for now both builds guard identically and this stays the pre-flight.
	if err := swg.CheckEgressDestination(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	if IsWSUpgrade(req) {
		return b.roundTripWS(req)
	}
	return b.roundTripHTTP(req)
}

// engineRequest converts a decided *http.Request into what the engine takes. The header drops mirror the wire
// host's: curl owns Content-Length/Transfer-Encoding for the body it sends (a duplicate Content-Length is the
// Akamai-loop class of defect), and Expect would make curl wait on a 100-continue.
func engineRequest(req *http.Request) (engine.Request, error) {
	out := engine.Request{Method: req.Method, URL: req.URL.String()}
	if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return engine.Request{}, fmt.Errorf("read request body: %w", err)
		}
		out.Body = body
	}
	for _, line := range reorigHeaderLines(req.Header) {
		lname := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lname, "content-length:") || strings.HasPrefix(lname, "transfer-encoding:") ||
			strings.HasPrefix(lname, "expect:") {
			continue
		}
		out.HeaderLines = append(out.HeaderLines, line)
	}
	return out, nil
}

func (b *roundTripper) roundTripHTTP(req *http.Request) (*http.Response, error) {
	ereq, err := engineRequest(req)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	sink := &responseSink{hdr: http.Header{}, pw: pw, ready: make(chan struct{})}
	go func() {
		engine.Reoriginate(sink, req.Context(), ereq)
		// The engine returned. If it never wrote a head, RoundTrip is still waiting — release it with the
		// failure rather than leaving the caller blocked on a response that will not come.
		sink.finish(pw)
	}()
	<-sink.ready
	if sink.status == 0 {
		return nil, fmt.Errorf("embedded egress: engine produced no response")
	}
	return &http.Response{
		StatusCode:    sink.status,
		Status:        http.StatusText(sink.status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        sink.hdr,
		Body:          pr,
		Request:       req,
		ContentLength: -1,
	}, nil
}

// responseSink is the engine's http.ResponseWriter when there is no HTTP server: header/status are captured,
// body bytes go into a pipe that becomes the Response.Body. Flush is a no-op because io.Pipe is already
// unbuffered — a write is visible to the reader immediately, which is what streaming needs.
type responseSink struct {
	hdr       http.Header
	pw        *io.PipeWriter
	status    int
	ready     chan struct{}
	readyOnce sync.Once
	finishErr error
}

func (s *responseSink) Header() http.Header { return s.hdr }

func (s *responseSink) WriteHeader(code int) {
	if s.status != 0 {
		return
	}
	s.status = code
	s.readyOnce.Do(func() { close(s.ready) })
}

func (s *responseSink) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.WriteHeader(http.StatusOK)
	}
	return s.pw.Write(p)
}

func (s *responseSink) Flush() {}

// finish closes the body pipe and, if the engine never produced a head, unblocks the waiting RoundTrip.
func (s *responseSink) finish(pw *io.PipeWriter) {
	_ = pw.Close()
	s.readyOnce.Do(func() { close(s.ready) })
}

func (b *roundTripper) roundTripWS(req *http.Request) (*http.Response, error) {
	ereq, err := engineRequest(req)
	if err != nil {
		return nil, err
	}
	edgeSide, engineSide := newBufferedDuplex()

	connected := make(chan struct{})
	relayErr := make(chan error, 1)
	go func() {
		relayErr <- engine.RelayWS(ereq, func() (io.ReadWriter, error) {
			close(connected)
			return engineSide, nil
		})
		edgeSide.Close()
	}()

	select {
	case <-connected:
	case err := <-relayErr:
		// Failed before the origin accepted — report why, exactly as the sidecar build surfaces the broker's 502.
		edgeSide.Close()
		if err == nil {
			err = fmt.Errorf("relay ended before connect")
		}
		return nil, fmt.Errorf("embedded ws: %w", err)
	}

	return &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}},
		Body:    edgeSide,
		Request: req,
	}, nil
}
