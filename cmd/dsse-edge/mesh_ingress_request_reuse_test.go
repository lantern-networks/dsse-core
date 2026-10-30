package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type reuseMeshTransport struct {
	in  chan tunnel.Frame
	out chan tunnel.Frame
}

func (t *reuseMeshTransport) ReadJSON(value any) error {
	frame, ok := <-t.in
	if !ok {
		return io.EOF
	}
	*(value.(*tunnel.Frame)) = frame
	return nil
}

func (t *reuseMeshTransport) WriteJSON(value any) error {
	t.out <- value.(tunnel.Frame)
	return nil
}

func (*reuseMeshTransport) Close() error { return nil }

type reuseMeshConn struct {
	reads     chan []byte
	closed    chan struct{}
	closedTwo chan struct{}
	writes    chan []byte
	mu        sync.Mutex
	closeN    int
}

func newReuseMeshConn() *reuseMeshConn {
	return &reuseMeshConn{
		reads: make(chan []byte, 2), closed: make(chan struct{}), closedTwo: make(chan struct{}), writes: make(chan []byte, 2),
	}
}

func (c *reuseMeshConn) Read(p []byte) (int, error) {
	data := <-c.reads
	if data == nil {
		return 0, io.EOF
	}
	return copy(p, data), nil
}

func (c *reuseMeshConn) Write(p []byte) (int, error) {
	data := append([]byte(nil), p...)
	c.writes <- data
	return len(p), nil
}

func (c *reuseMeshConn) Close() error {
	c.mu.Lock()
	c.closeN++
	switch c.closeN {
	case 1:
		close(c.closed)
	case 2:
		close(c.closedTwo)
	}
	c.mu.Unlock()
	return nil
}

type reuseMeshDialer struct {
	mu    sync.Mutex
	conns []*reuseMeshConn
	index int
}

func (d *reuseMeshDialer) OpenTCPConnection(context.Context, edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.index >= len(d.conns) {
		return nil, errors.New("unexpected mesh dial")
	}
	conn := d.conns[d.index]
	d.index++
	return conn, nil
}

func waitReuseMeshFrame(t *testing.T, out <-chan tunnel.Frame) tunnel.Frame {
	t.Helper()
	select {
	case frame := <-out:
		return frame
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mesh response")
		return tunnel.Frame{}
	}
}

func waitReuseMeshSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for old mesh handler")
	}
}

func TestMeshIngressOldReadPumpCannotAffectReopenedRequestID(t *testing.T) {
	first, second := newReuseMeshConn(), newReuseMeshConn()
	transport := &reuseMeshTransport{in: make(chan tunnel.Frame, 4), out: make(chan tunnel.Frame, 8)}
	dialer := &reuseMeshDialer{conns: []*reuseMeshConn{first, second}}
	done := make(chan error, 1)
	go func() { done <- serveMeshIngressTunnel(context.Background(), transport, dialer, "tenant", nil) }()
	t.Cleanup(func() {
		close(transport.in)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("mesh ingress did not stop")
		}
		second.reads <- nil // release the fake backend read left in flight
	})

	open, err := edgeplane.EdgeTCPOpenFrameForTarget("reuse", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app", Host: "private.internal", Port: 443,
	}, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		t.Fatal(err)
	}
	transport.in <- open
	if result := waitReuseMeshFrame(t, transport.out); result.Type != tunnel.FrameTCPOpenResult || result.Error != "" {
		t.Fatalf("first open: %#v", result)
	}
	transport.in <- tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: open.RequestID, Direction: tunnel.TCPDirectionRemote, CloseReason: tunnel.TCPCloseReasonEOF}
	waitReuseMeshSignal(t, first.closed)
	transport.in <- open
	if result := waitReuseMeshFrame(t, transport.out); result.Type != tunnel.FrameTCPOpenResult || result.Error != "" {
		t.Fatalf("replacement open: %#v", result)
	}

	// A read that was already in flight on the first backend completes after
	// its remote close and after the replacement has the same request ID.
	first.reads <- []byte("late")
	first.reads <- nil
	waitReuseMeshSignal(t, first.closedTwo)
	transport.in <- tunnel.Frame{Type: tunnel.FrameTCPData, RequestID: open.RequestID,
		Direction: tunnel.TCPDirectionUp, Data: base64.StdEncoding.EncodeToString([]byte("new"))}
	select {
	case data := <-second.writes:
		if string(data) != "new" {
			t.Fatalf("replacement backend received %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old read pump removed or closed the replacement handler")
	}
	select {
	case frame := <-transport.out:
		if frame.Type == tunnel.FrameTCPData || frame.Type == tunnel.FrameTCPClose {
			t.Fatalf("old read pump sent a late frame for replacement ID: %#v", frame)
		}
	default:
	}
}

func TestMeshIngressRejectsDuplicateActiveRequestID(t *testing.T) {
	first, second := newReuseMeshConn(), newReuseMeshConn()
	transport := &reuseMeshTransport{in: make(chan tunnel.Frame, 3), out: make(chan tunnel.Frame, 3)}
	dialer := &reuseMeshDialer{conns: []*reuseMeshConn{first, second}}
	done := make(chan error, 1)
	go func() { done <- serveMeshIngressTunnel(context.Background(), transport, dialer, "tenant", nil) }()
	t.Cleanup(func() {
		close(transport.in)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("mesh ingress did not stop")
		}
		first.reads <- nil
	})
	open, err := edgeplane.EdgeTCPOpenFrameForTarget("duplicate", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app", Host: "private.internal", Port: 443,
	}, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		t.Fatal(err)
	}
	transport.in <- open
	if result := waitReuseMeshFrame(t, transport.out); result.Error != "" {
		t.Fatalf("first open: %#v", result)
	}
	transport.in <- open
	if result := waitReuseMeshFrame(t, transport.out); result.Type != tunnel.FrameTCPOpenResult || result.Error == "" {
		t.Fatalf("duplicate active ID was accepted: %#v", result)
	}
	dialer.mu.Lock()
	dials := dialer.index
	dialer.mu.Unlock()
	if dials != 1 {
		t.Fatalf("duplicate active ID reached backend dial %d times", dials)
	}
}
