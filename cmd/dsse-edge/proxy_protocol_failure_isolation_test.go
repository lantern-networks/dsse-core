package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyProtocolMalformedPeerDoesNotStopHTTPListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newProxyProtocolListener(raw, parseTrustedFrontDoors("127.0.0.1"))
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	bad, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(bad, "PROXY "+strings.Repeat("x", proxyProtocolV1MaxLine)+"\r\n")
	_ = bad.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, _ = bad.Read(b[:])
	_ = bad.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Get("http://" + raw.Addr().String())
	if err != nil {
		select {
		case serveErr := <-done:
			t.Fatalf("one malformed peer stopped listener: %v; next request: %v", serveErr, err)
		default:
			t.Fatalf("next request failed: %v", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("next request status=%d", resp.StatusCode)
	}
}

func TestProxyProtocolOverlongHeaderRejectedWithoutReadingFurther(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan error, 1)
	go func() { _, err := proxyProtocolConn(server); done <- err }()
	// Exactly fill the permitted header buffer without a newline. A bounded
	// parser can reject now; ReadString would keep waiting and allocating.
	_, err := io.WriteString(client, "PROXY "+strings.Repeat("x", proxyProtocolV1MaxLine-6))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("overlong header accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("parser read beyond the maximum header length")
	}
}
