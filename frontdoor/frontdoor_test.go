package frontdoor

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientIPBelievesTheHeaderOnlyFromATrustedProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.77.0.5:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.77.0.5")
	if got := ClientIP(r, nil); got != "10.77.0.5" {
		t.Fatalf("with no trusted proxies the header was believed: %s", got)
	}
	if got := ClientIP(r, ParseTrustedNets("10.77.0.5")); got != "203.0.113.9" {
		t.Fatalf("from a trusted proxy the rightmost non-proxy entry is the client: %s", got)
	}
	r.RemoteAddr = "198.51.100.4:4000"
	if got := ClientIP(r, ParseTrustedNets("10.77.0.5")); got != "198.51.100.4" {
		t.Fatalf("a header from an untrusted connection was believed: %s", got)
	}
}

func TestTokenBucketRefillsAndKeepsKeysApart(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := NewTokenBucket(1, 2)
	b.Now = func() time.Time { return now }
	if !b.Allow("a") || !b.Allow("a") || b.Allow("a") {
		t.Fatal("burst of two was not honoured")
	}
	if !b.Allow("b") {
		t.Fatal("another key shares the first key's bucket")
	}
	now = now.Add(time.Second)
	if !b.Allow("a") {
		t.Fatal("a second's refill did not arrive")
	}
}

func TestTheListenerReportsTheAddressATrustedDoorDeclares(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewProxyProtocolListener(raw, ParseTrustedNets("127.0.0.1"))
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.RemoteAddr)) })}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("PROXY TCP4 203.0.113.9 127.0.0.1 40000 443\r\nGET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 64)
	n, _ := resp.Body.Read(body)
	if got := string(body[:n]); got != "203.0.113.9:40000" {
		t.Fatalf("the declared address was not reported: %q", got)
	}
}
