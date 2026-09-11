package edgeplane

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The h2 Extended-CONNECT (RFC 8441) WebSocket path had NO test, even though the Edge advertises "h2" to every
// intercepted client — so it is the path Chrome and desktop apps take to an intercepted origin. #28 ("the app
// sends but never receives") was reported with client->origin = 0 bytes, so these tests assert the two
// directions independently: a break in either one is the reported symptom.

// h2TunnelRecorder is a minimal h2 http.ResponseWriter that records the status and every body write. It
// implements http.Flusher because the tunnel only streams when it can flush after each frame.
type h2TunnelRecorder struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	body    []byte
	flushes int
}

func (w *h2TunnelRecorder) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *h2TunnelRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *h2TunnelRecorder) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = code
	}
}

func (w *h2TunnelRecorder) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushes++
}

func (w *h2TunnelRecorder) snapshot() (int, string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status, string(w.body), w.flushes
}

// newH2WebSocketTunnelFixture wires the writer under test to a fake origin (originSide of a net.Pipe) and a
// fake client send-stream (the h2 request body). Returns the recorder, the client's writer, the origin end, and
// a channel carrying the tunnel's return value.
func newH2WebSocketTunnelFixture(t *testing.T, ctx context.Context) (*h2TunnelRecorder, *io.PipeWriter, net.Conn, <-chan error) {
	t.Helper()
	edgeSide, originSide := net.Pipe()
	clientBody, clientWriter := io.Pipe()

	recorder := &h2TunnelRecorder{header: http.Header{}}
	writer := &networkExtensionLabTLSHTTP2WebSocketWriter{
		NetworkExtensionLabTLSHTTP2StatusWriter: &NetworkExtensionLabTLSHTTP2StatusWriter{ResponseWriter: recorder},
		clientBody:                              clientBody,
		clientCtx:                               ctx,
	}
	// The re-originated upstream 101; its Body IS the bidirectional tunnel to the origin.
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Sec-Websocket-Protocol": {"json.reliable.webpubsub.azure.v1"}},
		Body:       edgeSide,
	}

	done := make(chan error, 1)
	go func() { done <- writer.TunnelSWGHTTPEgressWebSocket(resp) }()
	t.Cleanup(func() {
		_ = clientWriter.Close()
		_ = originSide.Close()
	})
	return recorder, clientWriter, originSide, done
}

// The client's WebSocket frames must reach the origin. #28 was reported as client->origin = 0 bytes, which
// starves the origin of PONGs and makes it drop the WS with "keepalive ping timeout" — the reply never arrives.
func TestH2WebSocketTunnelRelaysClientToOrigin(t *testing.T) {
	_, clientWriter, originSide, _ := newH2WebSocketTunnelFixture(t, context.Background())

	const frame = "client-websocket-frame"
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientWriter.Write([]byte(frame))
		writeErr <- err
	}()

	_ = originSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(originSide, got); err != nil {
		t.Fatalf("origin never received the client's frame (#28 client->origin=0): %v", err)
	}
	if string(got) != frame {
		t.Fatalf("origin received %q, want %q", got, frame)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write failed: %v", err)
	}
}

// The origin's frames must reach the client, and each must be FLUSHED — an h2 stream that buffers delivers the
// reply only when the tunnel closes, which is indistinguishable from "never received" to a chat app.
func TestH2WebSocketTunnelStreamsOriginToClientAndFlushes(t *testing.T) {
	recorder, _, originSide, _ := newH2WebSocketTunnelFixture(t, context.Background())

	const frame = "origin-websocket-frame"
	_ = originSide.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := originSide.Write([]byte(frame)); err != nil {
		t.Fatalf("origin write failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		status, body, flushes := recorder.snapshot()
		if body == frame {
			// RFC 8441: Extended CONNECT is answered 200 (not 101) and the h2 stream becomes the tunnel.
			if status != http.StatusOK {
				t.Fatalf("client saw status %d, want 200 (RFC 8441 Extended CONNECT)", status)
			}
			if flushes == 0 {
				t.Fatal("origin frame was written but never flushed — the reply would sit buffered (#28)")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client never received the origin's frame: body=%q status=%d", body, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The negotiated subprotocol must be carried back to the client; a WS client that asked for a subprotocol and
// gets none may close the connection immediately.
func TestH2WebSocketTunnelCarriesNegotiatedSubprotocol(t *testing.T) {
	recorder, _, originSide, _ := newH2WebSocketTunnelFixture(t, context.Background())

	// Force the handshake to have been written by making the origin send one frame.
	_ = originSide.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := originSide.Write([]byte("x")); err != nil {
		t.Fatalf("origin write failed: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, body, _ := recorder.snapshot(); body == "x" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("origin frame never reached the client")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := recorder.Header().Get("Sec-WebSocket-Protocol"); got != "json.reliable.webpubsub.azure.v1" {
		t.Fatalf("Sec-WebSocket-Protocol = %q, want the origin's negotiated value", got)
	}
}

// When the client disconnects, the leak guard must close the origin connection: otherwise the origin->client
// io.Copy blocks forever on an idle-but-open WS and leaks the goroutine AND the origin socket.
func TestH2WebSocketTunnelClosesOriginWhenClientDisconnects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, _, originSide, done := newH2WebSocketTunnelFixture(t, ctx)

	cancel() // the h2 stream reset / client went away

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not return after the client disconnected — goroutine + origin conn leak")
	}
	// The origin side must observe the close rather than hanging on a live-but-idle connection.
	_ = originSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := originSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("origin connection still open after the client disconnected")
	}
}

// The h2->h1 rewrite and the broker's WS detection were written in different files; if they disagree, an
// Extended-CONNECT WebSocket is re-originated as an ORDINARY HTTP request, the origin answers 400/426, and the
// WS never opens — the app sends and never receives (#28). Pin the contract between them.
func TestPreparedH2WebSocketForwardRequestIsDetectedAsWSUpgrade(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "https://chatgpt.com/backend-api/wham/remote/control/server", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Go's h2 server surfaces the RFC 8441 pseudo-header to handlers as a normal header key.
	req.Header.Set(":protocol", "websocket")

	if !isNetworkExtensionLabTLSH2WebSocketConnect(req) {
		t.Fatal("an h2 Extended CONNECT websocket handshake was not recognised")
	}
	if err := prepareNetworkExtensionLabTLSH2WebSocketForwardRequest(req); err != nil {
		t.Fatalf("prepare forward request: %v", err)
	}

	if !BrokerIsWSUpgrade(req) {
		t.Fatalf("the rewritten forward request is NOT seen as a WS upgrade by the broker egress "+
			"(Connection=%q Upgrade=%q) — it would be re-originated as plain HTTP and the WS would never open (#28)",
			req.Header.Get("Connection"), req.Header.Get("Upgrade"))
	}
	if req.Method != http.MethodGet {
		t.Fatalf("forward method = %q, want GET (h1 WS upgrade)", req.Method)
	}
	if req.Header.Get("Sec-WebSocket-Key") == "" {
		t.Fatal("no Sec-WebSocket-Key minted — an h1 origin rejects the handshake")
	}
	if req.Header.Get("Sec-WebSocket-Version") != "13" {
		t.Fatalf("Sec-WebSocket-Version = %q, want 13", req.Header.Get("Sec-WebSocket-Version"))
	}
	// HTTP/2 pseudo-headers are invalid over http/1.1 and must not survive the rewrite.
	for name := range req.Header {
		if strings.HasPrefix(name, ":") {
			t.Fatalf("pseudo-header %q survived the h2->h1 rewrite", name)
		}
	}
}
