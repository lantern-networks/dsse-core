package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// syncBuffer is a concurrency-safe sink for the client-facing direction.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// The #28 localisation rested on ws_tunnel_closed reporting client_to_origin_bytes=0. Windows disproved that
// number directly: 600 bytes sent to wss://ws.postman-echo.com/raw came back as 608 bytes of echo — so the
// upstream direction demonstrably carried them — while the Edge logged client_to_origin_bytes=0.
//
// The cause was the counter, not the datapath. Taking io.Copy's return value only records a total when that
// copy RETURNS, and when the origin closes first the tunnel tears down while the client->origin copy is still
// blocked reading the client. That direction therefore always reported 0 for exactly the flows worth
// measuring. This reproduces that shape — bytes upstream, then the ORIGIN closes first — and pins the count.
func TestWebSocketTunnelCountsClientToOriginWhenOriginClosesFirst(t *testing.T) {
	edgeSide, originSide := net.Pipe()
	clientBody, clientWriter := io.Pipe()
	downstream := &syncBuffer{}

	const clientPayload = 600
	const originPayload = 608

	type result struct {
		c2o, o2c int64
		reason   string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		c2o, o2c, reason, err := edgeplane.CopyNetworkExtensionLabTLSWebSocketTunnelCounted(context.Background(), clientBody, downstream, edgeSide)
		done <- result{c2o, o2c, reason, err}
	}()

	// The client sends its frames upstream.
	go func() {
		_, _ = clientWriter.Write(bytes.Repeat([]byte("c"), clientPayload))
	}()

	// The origin receives them, echoes a reply, then CLOSES FIRST — the ordering that zeroed the counter.
	_ = originSide.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(originSide, make([]byte, clientPayload)); err != nil {
		t.Fatalf("origin did not receive the client's %d bytes: %v", clientPayload, err)
	}
	if _, err := originSide.Write(bytes.Repeat([]byte("o"), originPayload)); err != nil {
		t.Fatalf("origin write failed: %v", err)
	}
	_ = originSide.Close()

	select {
	case got := <-done:
		if got.c2o != clientPayload {
			t.Fatalf("client_to_origin_bytes = %d, want %d — the counter contradicts bytes the origin provably received (#28)", got.c2o, clientPayload)
		}
		if got.o2c != originPayload {
			t.Fatalf("origin_to_client_bytes = %d, want %d", got.o2c, originPayload)
		}
		// The ORIGIN ended this one. Misreporting it as a client/Edge teardown would send an operator hunting
		// for a fault on our side of a WebSocket that closed normally.
		if got.reason != "origin_closed" {
			t.Fatalf("reason = %q, want origin_closed", got.reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not return after the origin closed")
	}

	if downstream.Len() != originPayload {
		t.Fatalf("client received %d bytes, want %d", downstream.Len(), originPayload)
	}
}

// The mirror case: the CLIENT's send side ends first (a half-close) while the origin keeps streaming. The
// origin-facing total must still be true when the tunnel finally closes.
func TestWebSocketTunnelCountsOriginToClientAfterClientHalfClose(t *testing.T) {
	edgeSide, originSide := net.Pipe()
	clientBody, clientWriter := io.Pipe()
	downstream := &syncBuffer{}

	type result struct {
		c2o, o2c int64
		reason   string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		c2o, o2c, reason, err := edgeplane.CopyNetworkExtensionLabTLSWebSocketTunnelCounted(context.Background(), clientBody, downstream, edgeSide)
		done <- result{c2o, o2c, reason, err}
	}()

	// The client sends a little, then half-closes its send side.
	if _, err := clientWriter.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// Drain what the client sent so the copy is not left blocked on the unbuffered pipe.
	_ = originSide.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(originSide, make([]byte, 5)); err != nil {
		t.Fatalf("origin did not receive the client's bytes: %v", err)
	}
	_ = clientWriter.Close()

	// The origin keeps streaming AFTER the client's half-close, then finishes.
	if _, err := originSide.Write(bytes.Repeat([]byte("o"), 128)); err != nil {
		t.Fatalf("origin write after half-close failed: %v", err)
	}
	_ = originSide.Close()

	select {
	case got := <-done:
		if got.c2o != 5 {
			t.Fatalf("client_to_origin_bytes = %d, want 5", got.c2o)
		}
		if got.o2c != 128 {
			t.Fatalf("origin_to_client_bytes = %d, want 128 — the post-half-close stream must still be counted", got.o2c)
		}
		// The origin ended it, even though the client had half-closed first: still not an Edge teardown.
		if got.reason != "origin_closed" {
			t.Fatalf("reason = %q, want origin_closed", got.reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not return after the origin closed")
	}
}

// The one exit where the EDGE ends a WebSocket the origin was still streaming on. The ChatGPT desktop app
// reports its "pubsub transport" closing 30 times against 22 opens; if the Edge is the one doing that, this is
// the reason that will say so — and its category names the error that triggered it.
func TestWebSocketTunnelReportsAClientSideErrorTeardown(t *testing.T) {
	edgeSide, originSide := net.Pipe()
	clientBody, clientWriter := io.Pipe()
	downstream := &syncBuffer{}

	type result struct {
		reason string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, _, reason, err := edgeplane.CopyNetworkExtensionLabTLSWebSocketTunnelCounted(context.Background(), clientBody, downstream, edgeSide)
		done <- result{reason, err}
	}()

	// The client's send side fails with something that is NOT a clean EOF — a reset, not a half-close.
	_ = clientWriter.CloseWithError(errors.New("connection reset by peer"))

	select {
	case got := <-done:
		if !strings.HasPrefix(got.reason, "client_error:") {
			t.Fatalf("reason = %q, want a client_error:<category> — an Edge-initiated teardown must be named as one", got.reason)
		}
		if got.err == nil {
			t.Fatal("a non-benign client error must be returned, not swallowed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not return after the client errored")
	}
	// The origin must have been torn down too — that is what makes this exit worth naming.
	_ = originSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := originSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("origin connection still open after the Edge tore the tunnel down")
	}
}
