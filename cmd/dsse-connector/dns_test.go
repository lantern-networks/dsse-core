package main

import (
	"context"
	"net"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// A mock UDP DNS server that reflects the query id into a canned (non-truncated) response.
func mockUDPDNS(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := []byte{0, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0} // response, TC=0
			if n >= 2 {
				resp[0], resp[1] = buf[0], buf[1] // reflect query id
			}
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func TestRunConnectorDNS_ResolvesViaInternalDNS(t *testing.T) {
	addr, stop := mockUDPDNS(t)
	defer stop()
	query := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	frame := tunnel.Frame{Type: tunnel.FrameDNSQuery, RequestID: "r1", DNSUpstream: addr, DNSQuery: tunnel.EncodeDNSMessage(query)}
	reachable := model.ConnectorReachableRoutes{CIDRs: []string{"127.0.0.0/8"}}
	out := runConnectorDNS(context.Background(), frame, reachable)
	if out.Error != "" {
		t.Fatalf("unexpected error: %s", out.Error)
	}
	resp, err := tunnel.DecodeDNSMessage(out.DNSResponse)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) < 2 || resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatalf("raw response must reflect the query id (SRV/passthrough preserved), got %v", resp)
	}
}

func TestRunConnectorDNS_SSRFGuardRefusesOutOfScope(t *testing.T) {
	query := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	// upstream 10.99.x is NOT within the connector's reachable 10.10.0.0/16 -> must be refused, not dialed.
	frame := tunnel.Frame{Type: tunnel.FrameDNSQuery, RequestID: "r1", DNSUpstream: "10.99.99.99:53", DNSQuery: tunnel.EncodeDNSMessage(query)}
	reachable := model.ConnectorReachableRoutes{CIDRs: []string{"10.10.0.0/16"}}
	out := runConnectorDNS(context.Background(), frame, reachable)
	if out.Error == "" {
		t.Fatal("an upstream outside the connector's reachable routes must be refused (SSRF guard)")
	}
}

func TestRunConnectorDNS_RejectsBadFrame(t *testing.T) {
	out := runConnectorDNS(context.Background(), tunnel.Frame{Type: tunnel.FrameDNSQuery, RequestID: "r1", DNSQuery: "!!notbase64"}, model.ConnectorReachableRoutes{})
	if out.Error == "" {
		t.Fatal("an undecodable query must be rejected")
	}
}
