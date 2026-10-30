package edgeplane

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeCopyTunnelPreservesBytesReadWithHTTPHeaders(t *testing.T) {
	upstream, echo := net.Pipe()
	defer upstream.Close()
	defer echo.Close()
	go func() { _, _ = io.Copy(echo, echo) }()
	srv := httptest.NewServer(NewNetworkExtensionRuntimeCopyTunnelHandler(NetworkExtensionRuntimeCopyTunnelHandlerConfig{
		TenantID: "tenant_test", Dialer: fakeRuntimeCopyTunnelDialer{conn: upstream},
	}))
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const payload = "first tunnel bytes"
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: edge\r\n%s: tenant_test\r\n%s: app.test\r\n%s: 443\r\n\r\n%s", NetworkExtensionRuntimeCopyTunnelPath,
		networkExtensionRuntimeCopyTunnelTenantHeader, networkExtensionRuntimeCopyTunnelHostHeader, networkExtensionRuntimeCopyTunnelPortHeader, payload)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("handshake: %q %v", status, err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("buffered tunnel payload lost: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
}

type shortTunnelWriter struct{}

func (shortTunnelWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestRuntimeCopyTunnelReportsShortWrite(t *testing.T) {
	var activity uint64
	n, err := copyNetworkExtensionRuntimeCopyTunnelTrackingActivity(shortTunnelWriter{}, strings.NewReader("payload"), &activity)
	if !errors.Is(err, io.ErrShortWrite) || n != 6 {
		t.Fatalf("copy lost bytes without reporting failure: n=%d err=%v", n, err)
	}
}
