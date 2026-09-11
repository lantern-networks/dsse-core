package edgeplane

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestNetworkExtensionRuntimeCopyTLSInterceptionDialerProbeOnlyDropsUnmatchedWithoutRawForward(t *testing.T) {
	base := &recordingNetworkExtensionRuntimeCopyTCPDialer{}
	dialer := NetworkExtensionRuntimeCopyTLSInterceptionDialer{
		Base:                   base,
		Intercepter:            NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"}),
		ProbeOnlyDropUnmatched: true,
	}
	conn, err := dialer.OpenTCPConnection(context.Background(), NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 5228,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	if len(base.routes) != 0 {
		t.Fatalf("base dialer routes = %#v, want no raw forward in probe-only drop mode", base.routes)
	}
	if !NetworkExtensionRuntimeCopyAllowsEmptyDownstream(conn) {
		t.Fatalf("probe-only dropped conn does not allow empty downstream")
	}

	session := &NetworkExtensionRuntimeCopySession{
		RequestID:     "test_probe_only_drop_unmatched",
		applicationID: "default_network_extension_tunnel",
		conn:          conn,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exchange, err := runNetworkExtensionRuntimeCopySessionExchange(ctx, session, []byte("background tcp payload"))
	if err != nil {
		t.Fatalf("runNetworkExtensionRuntimeCopySessionExchange returned error: %v", err)
	}
	if !exchange.sessionClosed {
		t.Fatalf("sessionClosed = false, want true for probe-only dropped conn")
	}
	if len(exchange.downstream) != 0 {
		t.Fatalf("downstream bytes = %d, want 0", len(exchange.downstream))
	}
}

// recordingNetworkExtensionRuntimeCopyTCPDialer is the edgeplane-local copy of the
// cmd/edge test helper (test helpers are duplicated across the package boundary
// rather than exported).
type recordingNetworkExtensionRuntimeCopyTCPDialer struct {
	routes []NetworkExtensionRuntimeCopyTCPRoute
	conn   io.ReadWriteCloser
	err    error
}

func (dialer *recordingNetworkExtensionRuntimeCopyTCPDialer) OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	dialer.routes = append(dialer.routes, route)
	if dialer.err != nil {
		return nil, dialer.err
	}
	return dialer.conn, nil
}
