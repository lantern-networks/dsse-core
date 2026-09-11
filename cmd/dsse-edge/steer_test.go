package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// steerSNIRecordingDialer is a test interception dialer: it advertises SNI-based decision (so
// steerInterceptionUpstream peeks the ClientHello) and records the route it is dialed with.
type steerSNIRecordingDialer struct {
	routes []edgeplane.NetworkExtensionRuntimeCopyTCPRoute
	conn   io.ReadWriteCloser
}

func (d *steerSNIRecordingDialer) SNIBasedDecisionEnabled() bool { return true }

func (d *steerSNIRecordingDialer) OpenTCPConnection(_ context.Context, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	d.routes = append(d.routes, route)
	return d.conn, nil
}

func TestSteerServiceFamilyForPort(t *testing.T) {
	cases := map[int]string{
		443: "https", 8443: "https", 22: "ssh", 3389: "rdp", 445: "smb", 139: "smb",
		5985: "winrm", 135: "wmi_rpc", 5900: "vnc", 5432: "database", 1433: "database",
		9099: "", 0: "",
	}
	for port, want := range cases {
		if got := steerServiceFamilyForPort(port); got != want {
			t.Errorf("port %d: got %q want %q", port, got, want)
		}
	}
}

func TestSteerDecisionRequestBinding(t *testing.T) {
	req := steerDecisionRequest("t1", "10.0.0.5", 3389)
	if req.TenantID != "t1" || req.Destination != "10.0.0.5" || req.DestinationPort != 3389 ||
		req.ServiceFamily != "rdp" || req.Protocol != "tcp" || req.ActorType != "human" {
		t.Fatalf("steer decision request binding mismatch: %+v", req)
	}
}

// InterceptAll: a steered 443 flow must have its ClientHello SNI peeked and carried on the route handed to
// the interception dialer, even when route.Host is an IP literal (connect-by-IP). This is what makes
// steer-all https decrypt-all SNI-based, like the macOS NE path.
func TestSteerInterceptionUpstreamPeeksSNIForTLSFlow(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	// A real TLS client writes a genuine ClientHello with SNI; we only need the handshake's first record.
	go func() {
		tlsClient := tls.Client(clientSide, &tls.Config{ServerName: "accounts.google.com", InsecureSkipVerify: true})
		_ = tlsClient.Handshake()
	}()
	upstream := newRecordingNetworkExtensionRuntimeCopyTCPConnection(nil)
	dialer := &steerSNIRecordingDialer{conn: upstream}
	cc, gotUpstream, route, err := steerInterceptionUpstream(context.Background(), serverSide, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "192.0.2.10", Port: 443}, dialer)
	if err != nil {
		t.Fatalf("steerInterceptionUpstream returned error: %v", err)
	}
	if gotUpstream != upstream {
		t.Fatalf("upstream = %T, want recording interception conn", gotUpstream)
	}
	if cc == nil {
		t.Fatal("client conn = nil, want prefix-wrapped conn that replays the peeked ClientHello")
	}
	if route.SNI != "accounts.google.com" {
		t.Fatalf("route.SNI = %q, want accounts.google.com peeked from ClientHello", route.SNI)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].SNI != "accounts.google.com" || dialer.routes[0].Port != 443 {
		t.Fatalf("dialer routes = %+v, want one SNI-bearing 443 route", dialer.routes)
	}
}

// A non-TLS steered flow (e.g. rdp 3389) must NOT trigger a ClientHello peek (it would block on a
// non-TLS stream) and is routed with an empty SNI.
func TestSteerInterceptionUpstreamSkipsSNIPeekForNonTLS(t *testing.T) {
	_, serverSide := net.Pipe()
	defer serverSide.Close()
	upstream := newRecordingNetworkExtensionRuntimeCopyTCPConnection(nil)
	dialer := &steerSNIRecordingDialer{conn: upstream}
	_, gotUpstream, route, err := steerInterceptionUpstream(context.Background(), serverSide, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "10.0.0.9", Port: 3389}, dialer)
	if err != nil {
		t.Fatalf("steerInterceptionUpstream returned error: %v", err)
	}
	if gotUpstream != upstream {
		t.Fatalf("upstream = %T, want recording interception conn", gotUpstream)
	}
	if route.SNI != "" {
		t.Fatalf("non-TLS route.SNI = %q, want empty (no ClientHello peek)", route.SNI)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].Port != 3389 {
		t.Fatalf("dialer routes = %+v, want one 3389 route", dialer.routes)
	}
}

// Without an interception dialer, steerEgressForward falls back to the transparent forward proxy: it dials
// the authority. A guaranteed-closed port deterministically exercises (and fails) that dial branch.
func TestSteerEgressForwardWithoutInterceptionDialsAuthority(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAuthority := ln.Addr().String()
	_ = ln.Close() // now nothing is listening on closedAuthority
	_, serverSide := net.Pipe()
	defer serverSide.Close()
	err = steerEgressForward(context.Background(), serverSide, closedAuthority, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "127.0.0.1", Port: 0}, nil)
	if err == nil {
		t.Fatal("steerEgressForward to a closed authority returned nil, want dial failure error")
	}
}
