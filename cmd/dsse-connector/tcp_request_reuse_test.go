package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// A Close can race a read that has already completed in the OS but has not
// returned to the pump yet. Holding this read gives the old generation a
// deterministic chance to run after the peer's close frame.
type delayedConnectorReadConn struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *delayedConnectorReadConn) Read(p []byte) (int, error) {
	first := false
	c.once.Do(func() { close(c.entered); first = true })
	if !first {
		return 0, io.EOF
	}
	<-c.release
	return copy(p, "old-generation-bytes"), nil
}
func (*delayedConnectorReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (*delayedConnectorReadConn) Close() error                { return nil }

type sequentialConnectorDialer struct {
	mu    sync.Mutex
	conns []io.ReadWriteCloser
}

type contextAwareConnectorDialer struct{ conn io.ReadWriteCloser }

func (d *contextAwareConnectorDialer) OpenTCPConnection(ctx context.Context, _ connectorTCPRoute) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.conn, nil
}

func (dispatcher *connectorTunnelTCPDispatcher) requestIDPending(requestID string) bool {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.pending[requestID] != 0
}

func (d *sequentialConnectorDialer) OpenTCPConnection(context.Context, connectorTCPRoute) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil, io.EOF
	}
	c := d.conns[0]
	d.conns = d.conns[1:]
	return c, nil
}

func TestConnectorRequestIDCannotReopenWhileOldReadPumpCanStillPublish(t *testing.T) {
	old := &delayedConnectorReadConn{entered: make(chan struct{}), release: make(chan struct{})}
	otherConn := newCountingBlockingTCPConnection()
	newConn := newCountingBlockingTCPConnection()
	dialer := &sequentialConnectorDialer{conns: []io.ReadWriteCloser{old, otherConn, newConn}}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, fixedConnectorTestNow())
	defer dispatcher.CloseAll()
	writes := make(chan tunnel.Frame, 4)
	dispatcher.SetResponseWriter(func(frames []tunnel.Frame) error {
		for _, frame := range frames {
			writes <- frame
		}
		return nil
	})
	open := validConnectorTCPOpenFrame()
	open.RequestID = "req_reused_while_old_pump_running"
	result, err := dispatcher.HandleFrame(context.Background(), open)
	if err != nil || len(result) != 1 || result[0].Error != "" {
		t.Fatalf("first open: frames=%+v error=%v", result, err)
	}
	dispatcher.StartReadPumpForRequest(open.RequestID)
	select {
	case <-old.entered:
	case <-time.After(time.Second):
		t.Fatal("old read pump did not start")
	}
	_, err = dispatcher.HandleFrame(context.Background(), tunnel.Frame{
		Type: tunnel.FrameTCPClose, RequestID: open.RequestID,
		Direction: tunnel.TCPDirectionRemote, CloseReason: tunnel.TCPCloseReasonEOF,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The registry record is closed, but the old pump is still capable of
	// emitting a frame with this ID. Reuse must wait for that pump to finish.
	result, err = dispatcher.HandleFrame(context.Background(), open)
	if err != nil || len(result) != 1 || result[0].Error == "" {
		t.Fatalf("reopen admitted while old pump lives: frames=%+v error=%v", result, err)
	}
	other := open
	other.RequestID = "another_request_during_old_pump"
	result, err = dispatcher.HandleFrame(context.Background(), other)
	if err != nil || len(result) != 1 || result[0].Error != "" {
		t.Fatalf("unrelated request was blocked by old pump: frames=%+v error=%v", result, err)
	}
	close(old.release)
	deadline := time.Now().Add(time.Second)
	for dispatcher.requestIDPending(open.RequestID) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dispatcher.requestIDPending(open.RequestID) {
		t.Fatal("old request ID was not released after its pump finished")
	}
	for len(writes) > 0 {
		<-writes // old generation has completed before the new open
	}
	result, err = dispatcher.HandleFrame(context.Background(), open)
	if err != nil || len(result) != 1 || result[0].Error != "" {
		t.Fatalf("ID stayed reserved after old pump ended: frames=%+v error=%v", result, err)
	}
	select {
	case frame := <-writes:
		t.Fatalf("old pump published after a new open: %+v", frame)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestConnectorRequestIDReservedUntilExpiryCloseIsPublished(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("writer stopped")} {
		name := "success"
		if writeErr != nil {
			name = "send_failure"
		}
		t.Run(name, func(t *testing.T) {
			now := fixedConnectorTestNow()()
			dialer := &sequentialConnectorDialer{conns: []io.ReadWriteCloser{
				newRecordingTCPConnection(""), newRecordingTCPConnection(""),
			}}
			dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, func() time.Time { return now })
			defer dispatcher.CloseAll()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			dispatcher.SetResponseWriter(func([]tunnel.Frame) error {
				close(entered)
				<-release
				return writeErr
			})
			open := validConnectorTCPOpenFrame()
			open.RequestID = "request_expiring_during_publish"
			open.IdleTimeoutMillis = 1000
			if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
				t.Fatalf("open: frames=%+v error=%v", frames, err)
			}
			go func() { done <- dispatcher.PublishExpiredConnections(now.Add(1500 * time.Millisecond)) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("expiry writer did not start")
			}
			if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error == "" {
				t.Fatalf("reopen admitted before old close was published: frames=%+v error=%v", frames, err)
			}
			close(release)
			select {
			case err := <-done:
				if !errors.Is(err, writeErr) {
					t.Fatalf("expiry writer error = %v, want %v", err, writeErr)
				}
			case <-time.After(time.Second):
				t.Fatal("expiry writer did not finish")
			}
			if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
				t.Fatalf("reopen remained reserved after old close writer finished: frames=%+v error=%v", frames, err)
			}
		})
	}
}

func TestConnectorRequestIDReleasedAfterDialFailure(t *testing.T) {
	dialer := &sequentialConnectorDialer{conns: []io.ReadWriteCloser{nil, newRecordingTCPConnection("")}}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, fixedConnectorTestNow())
	defer dispatcher.CloseAll()
	open := validConnectorTCPOpenFrame()
	open.RequestID = "request_after_failed_dial"
	if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error == "" {
		t.Fatalf("first dial should fail: frames=%+v error=%v", frames, err)
	}
	if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
		t.Fatalf("request ID stayed reserved after failed dial: frames=%+v error=%v", frames, err)
	}
}

func TestConnectorRequestIDReleasedAfterContextCancellation(t *testing.T) {
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(),
		&contextAwareConnectorDialer{conn: newRecordingTCPConnection("")}, fixedConnectorTestNow())
	defer dispatcher.CloseAll()
	open := validConnectorTCPOpenFrame()
	open.RequestID = "request_after_cancelled_dial"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if frames, err := dispatcher.HandleFrame(ctx, open); err != nil || frames[0].Error == "" {
		t.Fatalf("cancelled dial should fail: frames=%+v error=%v", frames, err)
	}
	if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
		t.Fatalf("request ID stayed reserved after cancellation: frames=%+v error=%v", frames, err)
	}
}

func TestConnectorRequestIDReleasedAfterReadPumpSendFailure(t *testing.T) {
	old := &delayedConnectorReadConn{entered: make(chan struct{}), release: make(chan struct{})}
	dialer := &sequentialConnectorDialer{conns: []io.ReadWriteCloser{old, newRecordingTCPConnection("")}}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, fixedConnectorTestNow())
	defer dispatcher.CloseAll()
	dispatcher.SetResponseWriter(func([]tunnel.Frame) error { return errors.New("closed tunnel writer") })
	open := validConnectorTCPOpenFrame()
	open.RequestID = "request_after_send_failure"
	if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
		t.Fatalf("open: frames=%+v error=%v", frames, err)
	}
	dispatcher.StartReadPumpForRequest(open.RequestID)
	select {
	case <-old.entered:
	case <-time.After(time.Second):
		t.Fatal("read pump did not start")
	}
	close(old.release)
	deadline := time.Now().Add(time.Second)
	for dispatcher.requestIDPending(open.RequestID) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dispatcher.requestIDPending(open.RequestID) {
		t.Fatal("send failure did not release the old pump reservation")
	}
	if frames, err := dispatcher.HandleFrame(context.Background(), open); err != nil || frames[0].Error != "" {
		t.Fatalf("request ID stayed reserved after send failure: frames=%+v error=%v", frames, err)
	}
}

func TestConnectorCloseAllRefusesNewOpens(t *testing.T) {
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(),
		&contextAwareConnectorDialer{conn: newRecordingTCPConnection("")}, fixedConnectorTestNow())
	dispatcher.CloseAll()
	if frames, err := dispatcher.HandleFrame(context.Background(), validConnectorTCPOpenFrame()); err != nil || frames[0].Error == "" {
		t.Fatalf("closed dispatcher admitted a new connection: frames=%+v error=%v", frames, err)
	}
}
