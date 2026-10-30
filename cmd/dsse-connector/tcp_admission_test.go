package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

type admissionTestDialer struct {
	calls atomic.Int64
	dial  func(context.Context) (io.ReadWriteCloser, error)
}

func (d *admissionTestDialer) OpenTCPConnection(ctx context.Context, _ connectorTCPRoute) (io.ReadWriteCloser, error) {
	d.calls.Add(1)
	if d.dial != nil {
		return d.dial(ctx)
	}
	return newRecordingTCPConnection(""), nil
}

func TestConnectorConnectionLimitParsing(t *testing.T) {
	for _, test := range []struct {
		raw     string
		want    int
		invalid bool
	}{{"", 0, false}, {" 0 ", 0, false}, {"4096", 4096, false}, {"100000", 100000, false}, {"-1", 0, true}, {"many", 0, true}, {"9999999999999999999999999999", 0, true}} {
		got, err := parseConnectorTCPConnectionLimit(test.raw)
		if (err != nil) != test.invalid || got != test.want {
			t.Fatalf("parse %q = %d, %v", test.raw, got, err)
		}
	}
}

func TestConnectorAdmissionBudgetIsSharedAcrossAttachmentsAndReleased(t *testing.T) {
	base := &admissionTestDialer{}
	dialer := &connectorTCPAdmission{base: base, limit: 2}
	first := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, time.Now)
	second := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, time.Now)
	defer first.CloseAll()
	defer second.CloseAll()
	open := func(d *connectorTunnelTCPDispatcher, id string) []tunnel.Frame {
		t.Helper()
		frame := validConnectorTCPOpenFrame()
		frame.RequestID = id
		// Neither a lower nor a higher sender hint can change operator policy.
		frame.ConcurrentConnectionCap = 1
		frames, err := d.HandleFrame(context.Background(), frame)
		if err != nil {
			t.Fatal(err)
		}
		return frames
	}
	if got := open(first, "one"); len(got) != 1 || got[0].Error != "" {
		t.Fatalf("first: %+v", got)
	}
	if got := open(second, "two"); len(got) != 1 || got[0].Error != "" {
		t.Fatalf("second: %+v", got)
	}
	if got := open(second, "three"); len(got) != 1 || got[0].Error == "" {
		t.Fatalf("budget bypass: %+v", got)
	}
	if base.calls.Load() != 2 || dialer.snapshot()["active"] != 2 {
		t.Fatal("rejection dialed backend or changed existing admissions")
	}
	first.CloseAll()
	first.CloseAll()
	if dialer.snapshot()["active"] != 1 || second.registry.Count() != 1 {
		t.Fatal("disconnect affected another attachment or released twice")
	}
	if got := open(second, "three"); len(got) != 1 || got[0].Error != "" {
		t.Fatalf("released budget not reusable: %+v", got)
	}
	second.CloseAll()
	if dialer.snapshot()["active"] != 0 {
		t.Fatal("admission leaked after all attachments closed")
	}
}

func TestConnectorAdmissionDefaultDoesNotStopAt1024(t *testing.T) {
	dialer := &connectorTCPAdmission{base: &admissionTestDialer{}}
	var connections []io.ReadWriteCloser
	defer func() {
		for _, c := range connections {
			_ = c.Close()
		}
	}()
	for i := 0; i < 2048; i++ {
		conn, err := dialer.OpenTCPConnection(context.Background(), connectorTCPRoute{})
		if err != nil {
			t.Fatalf("open %d hit a hidden cap: %v", i+1, err)
		}
		connections = append(connections, conn)
	}
	if dialer.snapshot()["active"] != 2048 || dialer.snapshot()["max_connections"] != 0 {
		t.Fatal("unexpected default admission")
	}
}

func TestConnectorAdmissionReleasesFailedAndCanceledDials(t *testing.T) {
	for _, dial := range []func(context.Context) (io.ReadWriteCloser, error){
		func(context.Context) (io.ReadWriteCloser, error) { return nil, errors.New("failed") },
		func(ctx context.Context) (io.ReadWriteCloser, error) { <-ctx.Done(); return nil, ctx.Err() },
		func(context.Context) (io.ReadWriteCloser, error) { return nil, nil },
	} {
		dialer := &connectorTCPAdmission{base: &admissionTestDialer{dial: dial}, limit: 1}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := dialer.OpenTCPConnection(ctx, connectorTCPRoute{}); err == nil {
			t.Fatal("invalid dial succeeded")
		}
		if dialer.snapshot()["active"] != 0 {
			t.Fatal("failed dial leaked its reservation")
		}
	}
}

func TestConnectorAdmissionReservesBeforeConcurrentDials(t *testing.T) {
	const limit, attempts = 7, 100
	entered := make(chan struct{}, attempts)
	release := make(chan struct{})
	base := &admissionTestDialer{dial: func(context.Context) (io.ReadWriteCloser, error) {
		entered <- struct{}{}
		<-release
		return newRecordingTCPConnection(""), nil
	}}
	dialer := &connectorTCPAdmission{base: base, limit: limit}
	results := make(chan io.ReadWriteCloser, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			conn, _ := dialer.OpenTCPConnection(context.Background(), connectorTCPRoute{})
			results <- conn
		}()
	}
	defer func() {
		close(release)
		workers.Wait()
		close(results)
		for c := range results {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i := 0; i < limit; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("expected dials did not start")
		}
	}
	for i := 0; i < attempts-limit; i++ {
		select {
		case conn := <-results:
			if conn != nil {
				t.Fatal("pending dial returned prematurely")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("excess dial did not fail admission")
		}
	}
	if base.calls.Load() != limit || dialer.snapshot()["active"] != limit {
		t.Fatal("concurrent dials overbooked operator budget")
	}
}

type admissionDisconnectTransport struct {
	frame tunnel.Frame
	read  bool
}

func (c *admissionDisconnectTransport) ReadJSON(v any) error {
	if c.read {
		return io.EOF
	}
	c.read = true
	*(v.(*tunnel.Frame)) = c.frame
	return nil
}
func (*admissionDisconnectTransport) WriteJSON(any) error { return nil }

func TestConnectorTransportFailureClosesBudgetedBackend(t *testing.T) {
	client, backend := net.Pipe()
	defer backend.Close()
	base := &admissionTestDialer{dial: func(context.Context) (io.ReadWriteCloser, error) { return client, nil }}
	dialer := &connectorTCPAdmission{base: base, limit: 1}
	dispatcher := newConnectorTunnelTCPDispatcher(allowedConnectorTCPRoutes(), dialer, time.Now)
	transport := &admissionDisconnectTransport{frame: validConnectorTCPOpenFrame()}
	if err := handleConnectorTunnelConn(context.Background(), transport, "", dispatcher); !errors.Is(err, io.EOF) {
		t.Fatalf("transport result: %v", err)
	}
	if dialer.snapshot()["active"] != 0 || dispatcher.registry.Count() != 0 {
		t.Fatal("transport failure leaked socket or budget")
	}
	_ = backend.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprint(backend, "closed"); err == nil {
		t.Fatal("backend socket survived dead tunnel")
	}
}
