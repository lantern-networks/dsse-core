package interception_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/interception"
	"golang.org/x/net/http2"
)

// A client that negotiates HTTP/2 is intercepted as h2: the engine terminates the client's TLS, serves
// the decrypted multiplexed connection over HTTP/2, and reverse-proxies to the (also h2) origin.
func TestDecryptAllHTTP2(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ORIGIN-H2-OK proto="+r.Proto)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	target, _ := url.Parse(origin.URL)
	eng, err := interception.NewEngine([]string{"*"}, fwdHandler{target: target, client: origin.Client()}, interception.CAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(eng.RootCertPEM()) {
		t.Fatal("interception CA PEM not usable")
	}

	c, s := net.Pipe()
	go eng.Intercept(s, interception.Route{Host: "intercept.test", Port: 443})

	tc := tls.Client(c, &tls.Config{RootCAs: pool, ServerName: "intercept.test", NextProtos: []string{"h2"}})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("expected h2 negotiated, got %q", got)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://intercept.test/", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 roundtrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected an HTTP/2 response from the edge, got %s", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ORIGIN-H2-OK") {
		t.Fatalf("h2 decrypted forwarded response missing origin body: %q", string(body))
	}
}
