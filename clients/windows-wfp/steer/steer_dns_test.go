package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDNSProxyForwardsUDP verifies a UDP DNS query is forwarded to the Edge /steer/dns-query as
// application/dns-message and the raw DNS reply is returned to the sender (DNS-over-tunnel datapath).
func TestDNSProxyForwardsUDP(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}            // opaque DNS query bytes
	want := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C} // opaque DNS reply bytes

	var gotReq []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/steer/dns-query" || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotReq, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	p := newDNSProxy(transportConfig{}, srv.URL, false, nil) // plaintext path to the mock edge

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go p.serveUDP(pc)

	cli, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("read DNS response: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("response mismatch: got %x want %x", buf[:n], want)
	}
	if string(gotReq) != string(query) {
		t.Fatalf("forwarded query mismatch: got %x want %x", gotReq, query)
	}
}

// TestDNSProxyFailOpenForwardsUpstream verifies that with --fail-open, when the Edge is unreachable the proxy
// forwards the query to the captured upstream resolver instead of failing (the availability path during an
// Edge outage). It stands up a local UDP "upstream" that echoes a canned reply, points the proxy's edge at a
// dead address, and asserts resolve() returns the upstream answer.
func TestDNSProxyFailOpenForwardsUpstream(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C}

	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = upstream.WriteTo(want, addr)
		}
	}()

	// Edge points at a closed port so queryEdge fails fast -> fail-open kicks in.
	p := newDNSProxy(transportConfig{}, "http://127.0.0.1:1", true, newEdgeHealth(3, time.Second))
	p.setFallback([]string{upstream.LocalAddr().String()})

	got, err := p.resolve(query)
	if err != nil {
		t.Fatalf("fail-open resolve returned error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("fail-open answer mismatch: got %x want %x", got, want)
	}
}

func TestDNSProxyQueryURL(t *testing.T) {
	if p := newDNSProxy(transportConfig{}, "http://203.0.113.10:18090/", false, nil); p.queryURL != "http://203.0.113.10:18090/steer/dns-query" {
		t.Fatalf("plaintext url: %s", p.queryURL)
	}
	if p := newDNSProxy(transportConfig{enabled: true, host: "203.0.113.10:18543"}, "", false, nil); p.queryURL != "https://203.0.113.10:18543/steer/dns-query" {
		t.Fatalf("transport url: %s", p.queryURL)
	}
}
