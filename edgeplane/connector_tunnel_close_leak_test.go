package edgeplane

// Regression test: openConnectorTunnelTCPConn must release BOTH bridge goroutines when the EDGE side closes
// first — the common case (http.Transport reaping an idle pooled conn, an interactive ssh client
// disconnecting). This once leaked: the client->tunnel goroutine sent FrameTCPClose up and exited, the
// connector's dispatcher replied NOTHING to it (HandleFrame returns nil frames for FrameTCPClose —
// oss/cmd/dsse-connector/tcp_dialer.go), and the tunnel->client goroutine then blocked forever in
// `for frame := range streamCh`, pinning one goroutine + one Session.streams entry per edge-closed stream.
// The fix is that RegisterTCPStream's cleanup CLOSES the stream channel (idempotently, under s.mu) and both
// bridge goroutines run it.
//
// The fake transport below mimics the connector exactly at the decisive step: it acks the open and stays
// silent on an edge-sent close.

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// silentCloseTransport acks FrameTCPOpen with FrameTCPOpenResult and, like the real connector dispatcher,
// never replies to an edge-initiated FrameTCPClose.
type silentCloseTransport struct {
	opened chan string   // receives the RequestID of the open frame once written
	done   chan struct{} // closed by the test to release the Run loop
}

func (t *silentCloseTransport) WriteJSON(value any) error {
	frame, ok := value.(tunnel.Frame)
	if !ok {
		return errors.New("unexpected write type")
	}
	if frame.Type == tunnel.FrameTCPOpen {
		t.opened <- frame.RequestID
	}
	// FrameTCPClose from the edge: swallowed, no reply — the real dispatcher returns nil frames for it.
	return nil
}

func (t *silentCloseTransport) ReadJSON(value any) error {
	select {
	case requestID := <-t.opened:
		*(value.(*tunnel.Frame)) = tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: requestID}
		return nil
	case <-t.done:
		return errors.New("transport closed")
	}
}

func (t *silentCloseTransport) Close() error { return nil }

func goroutineStacksContain(needle string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), needle)
}

func TestConnectorTunnelTCPConnCallerCloseFirstReleasesTunnelBridge(t *testing.T) {
	transport := &silentCloseTransport{opened: make(chan string, 1), done: make(chan struct{})}
	defer close(transport.done)
	manager := tunnel.NewManagerWithRequestTimeout(2 * time.Second)
	session, _ := manager.Register("conn_lab_leak", "tun_lab_leak", transport)
	go func() { _ = session.Run() }()

	conn, err := openConnectorTunnelTCPConn(context.Background(), session, "app.internal", 443, "tenant_test")
	if err != nil {
		t.Fatalf("openConnectorTunnelTCPConn returned error: %v", err)
	}

	// The edge side closes first (idle pooled conn reaped / client disconnected).
	_ = conn.Close()

	// G1 must exit (its pipe read fails) and G2 must ALSO exit so cleanup() releases the stream registration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !goroutineStacksContain("CopyEdgeTCPTunnelToClient") {
			return // both bridge goroutines gone — no leak
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("tunnel->client bridge goroutine is still alive 2s after the caller closed: openConnectorTunnelTCPConn leaks one goroutine + one Session.streams entry every time the edge side closes first")
}
