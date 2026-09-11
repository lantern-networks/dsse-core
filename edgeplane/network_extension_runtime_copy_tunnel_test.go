package edgeplane

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeRuntimeCopyTunnelDialer struct {
	conn io.ReadWriteCloser
	err  error
}

func (f fakeRuntimeCopyTunnelDialer) OpenTCPConnection(_ context.Context, _ NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

// closeWriteRecordingConn is the smallest conn that lets a test observe CloseWrite/CloseRead being delegated.
type closeWriteRecordingConn struct {
	net.Conn
	closeWriteCalled bool
	closeReadCalled  bool
}

func (c *closeWriteRecordingConn) CloseWrite() error { c.closeWriteCalled = true; return nil }
func (c *closeWriteRecordingConn) CloseRead() error  { c.closeReadCalled = true; return nil }

// A regression guard: prefixedConn must delegate CloseWrite to the conn it embeds. Without it the tunnel
// bridge's halfCloseWriteSide fails its type assertion and falls back to closing BOTH directions instead of
// half-closing, which RSTs an intercepted flow in the middle of delivering its response — and is why an
// intercepted form's "next" did nothing.
func TestNetworkExtensionLabTLSPrefixedConnDelegatesCloseWrite(t *testing.T) {
	rec := &closeWriteRecordingConn{}
	prefixed := &NetworkExtensionLabTLSPrefixedConn{Conn: rec, Prefix: []byte("hello")}

	// It must be half-closeable through the same type assertion the tunnel bridge makes.
	if !halfCloseWriteSide(prefixed) {
		t.Fatalf("halfCloseWriteSide(prefixedConn) = false, want true (CloseWrite must be exposed)")
	}
	if !rec.closeWriteCalled {
		t.Fatalf("CloseWrite was not delegated to the embedded conn")
	}

	if cr, ok := interface{}(prefixed).(interface{ CloseRead() error }); ok {
		if err := cr.CloseRead(); err != nil {
			t.Fatalf("CloseRead: %v", err)
		}
		if !rec.closeReadCalled {
			t.Fatalf("CloseRead was not delegated to the embedded conn")
		}
	} else {
		t.Fatalf("prefixedConn does not expose CloseRead")
	}
}

// dialTunnel performs the HTTP hijack handshake and returns the raw tunnel conn.
func dialTunnel(t *testing.T, addr, tenant, host, port string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: edge\r\n%s: %s\r\n%s: %s\r\n%s: %s\r\n\r\n",
		NetworkExtensionRuntimeCopyTunnelPath,
		networkExtensionRuntimeCopyTunnelTenantHeader, tenant,
		networkExtensionRuntimeCopyTunnelHostHeader, host,
		networkExtensionRuntimeCopyTunnelPortHeader, port,
	)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read tunnel status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("tunnel status = %q, want 200 Connection Established", status)
	}
	return conn, br
}

func TestNetworkExtensionRuntimeCopyTunnelBridgesFullDuplex(t *testing.T) {
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	// Echo upstream: full-duplex round-trip without per-exchange lockstep.
	go func() { _, _ = io.Copy(upstreamB, upstreamB) }()

	handler := NewNetworkExtensionRuntimeCopyTunnelHandler(NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   fakeRuntimeCopyTunnelDialer{conn: upstreamA},
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	conn, br := dialTunnel(t, srv.Listener.Addr().String(), "tenant_lab_001", "dummy.local", "443")
	defer conn.Close()
	// Skip the rest of the HTTP response headers up to the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read established headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Send several payloads; each should echo back. Full-duplex: we can write the
	// next before reading is forced into lockstep with the previous.
	for _, payload := range []string{"hello", "world", "dsse"} {
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("read echo for %q: %v", payload, err)
		}
		if string(got) != payload {
			t.Fatalf("echo = %q, want %q", got, payload)
		}
	}
}

func TestNetworkExtensionRuntimeCopyTunnelHalfCloseKeepsReverseStreamAlive(t *testing.T) {
	// A real TCP upstream, so CloseWrite actually does something. The dialer returns the dialling side and the
	// test holds the accepted side — the upstream server — so it can drive both directions.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamLn.Close()
	upstreamServerCh := make(chan net.Conn, 1)
	go func() {
		serverConn, acceptErr := upstreamLn.Accept()
		if acceptErr != nil {
			return
		}
		upstreamServerCh <- serverConn
	}()
	upstreamClient, err := net.Dial("tcp", upstreamLn.Addr().String())
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}

	handler := NewNetworkExtensionRuntimeCopyTunnelHandler(NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   fakeRuntimeCopyTunnelDialer{conn: upstreamClient},
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	conn, br := dialTunnel(t, srv.Listener.Addr().String(), "tenant_lab_001", "dummy.local", "443")
	defer conn.Close()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read established headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	upstreamServer := <-upstreamServerCh
	defer upstreamServer.Close()

	// 1) client sends to upstream: the request.
	if _, err := conn.Write([]byte("request-bytes")); err != nil {
		t.Fatalf("client write request: %v", err)
	}
	gotRequest := make([]byte, len("request-bytes"))
	if _, err := io.ReadFull(upstreamServer, gotRequest); err != nil {
		t.Fatalf("upstream read request: %v", err)
	}
	if string(gotRequest) != "request-bytes" {
		t.Fatalf("upstream request = %q, want request-bytes", gotRequest)
	}

	// 2) the client half-closes its sending side only: the request is complete.
	clientTCP, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("client conn type %T is not *net.TCPConn", conn)
	}
	if err := clientTCP.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	// 3) the bridge propagates the client-to-upstream EOF as a write half-close on the upstream, so
	//    upstreamServer sees EOF on a read. Had it closed both, this would be a connection error instead.
	tail := make([]byte, 1)
	if _, err := upstreamServer.Read(tail); err != io.EOF {
		t.Fatalf("upstream read after client half-close = %v, want io.EOF", err)
	}

	// 4) the other direction is alive: proof the half-close did not cut it.
	if _, err := upstreamServer.Write([]byte("response-stream")); err != nil {
		t.Fatalf("upstream write response: %v", err)
	}
	gotResponse := make([]byte, len("response-stream"))
	if _, err := io.ReadFull(br, gotResponse); err != nil {
		t.Fatalf("client read response after half-close: %v", err)
	}
	if string(gotResponse) != "response-stream" {
		t.Fatalf("client response = %q, want response-stream", gotResponse)
	}

	// 5) once the upstream closes, both directions are done, the whole flow is torn down, and the client
	//    sees EOF.
	_ = upstreamServer.Close()
	if _, err := io.ReadAll(br); err != nil {
		// Anything in the connection-closed family is accepted, not only EOF: the point is that it closed.
		_ = err
	}
}

func TestNetworkExtensionRuntimeCopyTunnelIdleTimeoutTearsDownSilentFlow(t *testing.T) {
	// A flow with no bytes in either direction is torn down at idleTimeout — the bound on a peer that, after a
	// half-close, neither speaks nor closes.
	clientBridge, clientTest := net.Pipe()
	upstreamBridge, upstreamTest := net.Pipe()
	defer clientTest.Close()
	defer upstreamTest.Close()

	bridgeDone := make(chan struct{})
	go func() {
		bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(context.Background(), clientBridge, upstreamBridge, 40*time.Millisecond)
		close(bridgeDone)
	}()

	// Left silent, the watchdog fires and closes both ends; the client's read gives EOF or an error.
	_ = clientTest.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := clientTest.Read(buf); err == nil {
		t.Fatal("client read succeeded, want teardown error after idle timeout")
	}
	select {
	case <-bridgeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not return after idle teardown")
	}
}

func TestNetworkExtensionRuntimeCopyTunnelIdleTimeoutDoesNotCutActiveFlow(t *testing.T) {
	// One direction being silent does not matter while the other carries periodically: idle is a property of
	// the FLOW, and it holds across several idle windows.
	clientBridge, clientTest := net.Pipe()
	upstreamBridge, upstreamTest := net.Pipe()
	defer clientTest.Close()
	defer upstreamTest.Close()

	const idleTimeout = 60 * time.Millisecond
	bridgeDone := make(chan struct{})
	go func() {
		bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(context.Background(), clientBridge, upstreamBridge, idleTimeout)
		close(bridgeDone)
	}()

	// Six sends upstream-to-client at less than idleTimeout apart: about 120ms, more than two windows.
	for i := 0; i < 6; i++ {
		if _, err := upstreamTest.Write([]byte("tick")); err != nil {
			t.Fatalf("upstream write %d: %v", i, err)
		}
		got := make([]byte, len("tick"))
		_ = clientTest.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(clientTest, got); err != nil {
			t.Fatalf("client read tick %d (active reverse flow was cut?): %v", i, err)
		}
		if string(got) != "tick" {
			t.Fatalf("tick %d = %q, want tick", i, got)
		}
		time.Sleep(idleTimeout / 3)
	}

	// Stop the activity and it is torn down as idle: the safety net still works.
	select {
	case <-bridgeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not tear down after activity stopped")
	}
}

func TestNetworkExtensionRuntimeCopyTunnelHalfCloseStalledReverseReapsFast(t *testing.T) {
	// LEAK REGRESSION: a flow whose one direction half-closes WITHOUT HAVING SENT ANYTHING, and whose surviving
	// direction then STALLS, must be reaped on the SHORT half-close linger — not held for the full idle window.
	// This is the ABANDONED-client shape (Happy-Eyeballs race loser, connection-pool miss, closed tab) — measured
	// as 43 of 68 such flows on Windows. Held for the full window under connection churn these half-dead bridges
	// accumulate — each pinning a 32 KiB relay buffer + conn/TLS state + two goroutines — the goroutine/heap leak
	// that drove GC CPU to saturation.
	//
	// A half-close that FIRST SENT A REQUEST is a DIFFERENT shape (a reply may be pending) and keeps the full
	// window — see TestNetworkExtensionRuntimeCopyTunnelRequestSentHalfCloseKeepsFullWindow (the #28 fix).
	newTCPPair := func() (dialSide, acceptSide net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		accCh := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); accCh <- c }()
		d, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return d, <-accCh
	}
	clientConn, clientTest := newTCPPair()
	upstreamConn, upstreamTest := newTCPPair()
	defer clientTest.Close()
	defer upstreamTest.Close()

	const idleTimeout = 200 * time.Millisecond // half-close linger is idleTimeout/8 = 25ms

	bridgeDone := make(chan struct{})
	go func() {
		bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(context.Background(), clientConn, upstreamConn, idleTimeout)
		close(bridgeDone)
	}()

	// Client half-closes its send side (FIN) having sent NOTHING; the reverse stays open but the upstream sends
	// nothing — the abandoned-client shape.
	tc, ok := clientTest.(*net.TCPConn)
	if !ok {
		t.Fatalf("clientTest type %T is not *net.TCPConn", clientTest)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	// Must reap WELL WITHIN the full idle window (on the short linger). The old watchdog held it for ~2×idleTimeout.
	select {
	case <-bridgeDone:
	case <-time.After(idleTimeout - 40*time.Millisecond):
		t.Fatal("bridge did not reap the abandoned (nothing-sent) half-close on the short linger (connection leak)")
	}
}

func TestNetworkExtensionRuntimeCopyTunnelRequestSentHalfCloseKeepsFullWindow(t *testing.T) {
	// #28 REGRESSION: a flow that SENT A REQUEST and then half-closed its send side is awaiting a reply, NOT
	// abandoned. It must keep the FULL idle window — the reply may not begin within the short linger (a model
	// thinking, or egress latency on an AI-chat stream). The 2026-07-10 linger reaped these reply-pending flows
	// on ~idle/8, which is the ChatGPT-app "send works, receive never arrives" regression.
	newTCPPair := func() (dialSide, acceptSide net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		accCh := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); accCh <- c }()
		d, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return d, <-accCh
	}
	clientConn, clientTest := newTCPPair()
	upstreamConn, upstreamTest := newTCPPair()
	defer clientTest.Close()
	defer upstreamTest.Close()

	const idleTimeout = 400 * time.Millisecond // half-close linger = idleTimeout/8 = 50ms

	bridgeDone := make(chan struct{})
	go func() {
		bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(context.Background(), clientConn, upstreamConn, idleTimeout)
		close(bridgeDone)
	}()

	// Client sends a request, then half-closes its send side (FIN). The reply has not started yet.
	if _, err := clientTest.Write([]byte("GET /reply HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	tc := clientTest.(*net.TCPConn)
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	// Drain the request the bridge forwarded upstream, so the upstream socket does not fill and perturb timing.
	go func() { _, _ = io.Copy(io.Discard, upstreamTest) }()

	// It must NOT be reaped on the short linger (50ms): a reply-pending flow keeps the full window.
	select {
	case <-bridgeDone:
		t.Fatal("request-sent half-close was reaped on the short linger — this is the #28 regression")
	case <-time.After(idleTimeout / 2):
	}

	// The reply, arriving after the linger would have fired, still reaches the client — the flow was kept alive.
	if _, err := upstreamTest.Write([]byte("HTTP/1.1 200 OK\r\n\r\nhi")); err != nil {
		t.Fatalf("upstream reply write: %v", err)
	}
	_ = clientTest.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := clientTest.Read(buf)
	if err != nil {
		t.Fatalf("client read of the reply (flow was cut?): %v", err)
	}
	if !strings.Contains(string(buf[:n]), "hi") {
		t.Fatalf("client did not receive the reply body; got %q", buf[:n])
	}
}

func TestNetworkExtensionRuntimeCopyTunnelInteractiveIdleNeverCutsLiveFlow(t *testing.T) {
	// An interactive east-west flow (ssh) sets idle=0, an unlimited full window. With both directions open and
	// nothing flowing, the watchdog does not tear it down — thinking at a prompt does not cut the session. The
	// linger is finite but nothing has half-closed, so it never applies.
	clientBridge, clientTest := net.Pipe()
	upstreamBridge, upstreamTest := net.Pipe()
	defer clientTest.Close()
	defer upstreamTest.Close()

	const linger = 400 * time.Millisecond // poll = linger/4 = 100ms
	bridgeDone := make(chan struct{})
	go func() {
		BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(context.Background(), clientBridge, upstreamBridge, 0, linger)
		close(bridgeDone)
	}()

	// Wait silently for well past the linger, so the poll fires several times. With the full window it must
	// not be reaped.
	select {
	case <-bridgeDone:
		t.Fatal("interactive full-duplex idle flow was torn down (window=0 must never reap)")
	case <-time.After(3 * linger):
	}

	// Proof the flow is alive: bytes sent now still get through.
	if _, err := upstreamTest.Write([]byte("ping")); err != nil {
		t.Fatalf("upstream write after long idle: %v", err)
	}
	got := make([]byte, 4)
	_ = clientTest.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientTest, got); err != nil {
		t.Fatalf("client read after long idle (flow was cut?): %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("read = %q, want ping", got)
	}
}

func TestNetworkExtensionRuntimeCopyTunnelInteractiveHalfCloseStillReaps(t *testing.T) {
	// An unlimited full window does not disable the half-close handling even on an interactive flow: once one
	// direction has EOF'd, the finite linger reaps it, which is the bound on an abandoned client's leak.
	newTCPPair := func() (dialSide, acceptSide net.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		accCh := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); accCh <- c }()
		d, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return d, <-accCh
	}
	clientConn, clientTest := newTCPPair()
	upstreamConn, upstreamTest := newTCPPair()
	defer clientTest.Close()
	defer upstreamTest.Close()

	const linger = 120 * time.Millisecond
	bridgeDone := make(chan struct{})
	go func() {
		BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(context.Background(), clientConn, upstreamConn, 0, linger)
		close(bridgeDone)
	}()

	// The client half-closes its sending side WITHOUT having sent anything: the abandoned shape — a connection
	// pool's miss, for instance. The other direction is open but the upstream is silent. A client that sent
	// bytes before half-closing is treated as waiting for a reply and keeps the full window, so this case is
	// deliberately the zero-byte one.
	tc, ok := clientTest.(*net.TCPConn)
	if !ok {
		t.Fatalf("clientTest type %T is not *net.TCPConn", clientTest)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	// After the half-close it is reaped by the linger: even an unlimited full window does not leave it.
	select {
	case <-bridgeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("abandoned (nothing-sent) half-closed interactive flow was not reaped on the linger (leak countermeasure lost)")
	}
}

func TestNetworkExtensionRuntimeCopyTunnelRejectsTenantMismatch(t *testing.T) {
	handler := NewNetworkExtensionRuntimeCopyTunnelHandler(NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   fakeRuntimeCopyTunnelDialer{conn: nil},
	})
	req := httptest.NewRequest(http.MethodGet, NetworkExtensionRuntimeCopyTunnelPath, nil)
	req.Header.Set(networkExtensionRuntimeCopyTunnelTenantHeader, "tenant_other")
	req.Header.Set(networkExtensionRuntimeCopyTunnelHostHeader, "dummy.local")
	req.Header.Set(networkExtensionRuntimeCopyTunnelPortHeader, "443")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("tenant mismatch status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}
