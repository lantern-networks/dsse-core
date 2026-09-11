package edgeplane

import (
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// largeSourceConn returns total bytes from Read as fast as it can and discards Write: a stand-in for an upstream sending a large response.
type largeSourceConn struct {
	mu        sync.Mutex
	remaining int64
	buf       []byte
}

func (c *largeSourceConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > c.remaining {
		n = int(c.remaining)
	}
	if len(c.buf) < n {
		c.buf = make([]byte, n)
	}
	c.remaining -= int64(n)
	return copy(p, c.buf[:n]), nil
}
func (c *largeSourceConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *largeSourceConn) Close() error                { return nil }

// Measures the throughput of the Edge's tunnel handler and bridge ALONE, without the network extension's Swift side —
// so if this is fast the 340 KB/s came from the extension, and if it is slow it came from here.
func TestNetworkExtensionRuntimeCopyTunnelEdgeThroughput(t *testing.T) {
	const total = 50 * 1024 * 1024
	handler := NewNetworkExtensionRuntimeCopyTunnelHandler(NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   fakeRuntimeCopyTunnelDialer{conn: &largeSourceConn{remaining: total}},
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	conn, br := dialTunnel(t, srv.Listener.Addr().String(), "tenant_lab_001", "dummy.local", "443")
	defer conn.Close()
	start := time.Now()
	n, _ := io.Copy(io.Discard, br)
	elapsed := time.Since(start)
	t.Logf("edge tunnel throughput: bytes=%d elapsed=%s speed=%.1f MiB/s", n, elapsed, float64(n)/elapsed.Seconds()/(1024*1024))
}
