package edgeplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// A deterministic harness: drive an intercepted connection (an in-process pipe, serve, and h2) at high
// concurrency and measure whether every stream succeeds and how long it takes. Deterministic so a real
// site's flakiness is not part of the measurement, and so the difference between in-process transports —
// net.Pipe against loopback TCP — is seen by measuring rather than by argument.
func TestNetworkExtensionLabTLSInterceptionHTTP2ConcurrentThroughput(t *testing.T) {
	certNow := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time { return certNow })
	if err != nil {
		t.Fatalf("NewNetworkExtensionLabTLSInterception: %v", err)
	}
	// A handler returning a 64 KiB response, about the size of a JavaScript bundle.
	const bodySize = 64 * 1024
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443})
	if err != nil {
		t.Fatalf("OpenTCPConnection: %v", err)
	}
	defer conn.Close()
	roots := x509.NewCertPool()
	roots.AddCert(interception.rootCert)
	client := tls.Client(conn.(net.Conn), &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		Time:       func() time.Time { return certNow },
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if client.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN != h2")
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(client)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}

	const streams = 50
	start := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures int
	var totalBytes int64
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://accounts.google.com/bundle-%d.js", i), nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}
			n, err := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			mu.Lock()
			if err != nil || n != bodySize {
				failures++
			}
			totalBytes += n
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	mbps := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("intercept h2 throughput: streams=%d failures=%d bytes=%d elapsed=%s throughput=%.1f MiB/s",
		streams, failures, totalBytes, elapsed, mbps)
	if failures > 0 {
		t.Fatalf("%d/%d concurrent intercept streams failed", failures, streams)
	}
}
