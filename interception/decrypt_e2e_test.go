package interception_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/interception"
)

type fwdHandler struct {
	target *url.URL
	client *http.Client
}

func (h fwdHandler) ServeFlow(w http.ResponseWriter, r *http.Request, route interception.Route) {
	p := httputil.NewSingleHostReverseProxy(h.target)
	p.Transport = h.client.Transport
	p.ServeHTTP(w, r)
}

// TestDecryptAllEndToEnd proves the decrypt-all path: a client trusting the interception CA performs TLS
// to "intercept.test"; the engine terminates it with a leaf it signs, forwards the decrypted request to
// the origin, and returns the response — all visible/enforceable at the edge.
func TestDecryptAllEndToEnd(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ORIGIN-DECRYPTED-OK")
	}))
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

	tc := tls.Client(c, &tls.Config{RootCAs: pool, ServerName: "intercept.test"})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: intercept.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("inner TLS write: %v", err)
	}
	data, _ := io.ReadAll(tc)
	if !strings.Contains(string(data), "ORIGIN-DECRYPTED-OK") {
		t.Fatalf("decrypted forwarded response missing origin body; got %q", string(data))
	}
}
