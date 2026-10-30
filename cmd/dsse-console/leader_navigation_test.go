package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func consoleNavigationTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"cp-a.example", "cp-b.example", "console-a.example", "console-b.example", "console-c.example", "console.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: rawKey}))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

type consoleLeaderFixture struct {
	a, b   atomic.Bool
	calls  atomic.Int32
	trust  *tls.Config
	tls    *tls.Config
	ca, cb *httptest.Server
}

func newConsoleLeaderFixture(t *testing.T) *consoleLeaderFixture {
	t.Helper()
	f := &consoleLeaderFixture{}
	f.tls, f.trust = consoleNavigationTLS(t)
	makeCP := func(leader *atomic.Bool) *httptest.Server {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.calls.Add(1)
			if r.URL.Path != "/leader" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Error("leader probe forwarded browser credentials or wrong path")
			}
			if leader.Load() {
				io.WriteString(w, `{"leader":true}`)
			} else {
				w.WriteHeader(503)
				io.WriteString(w, `{"leader":false}`)
			}
		}))
		s.TLS = f.tls.Clone()
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	f.ca, f.cb = makeCP(&f.a), makeCP(&f.b)
	f.a.Store(true)
	return f
}
func (f *consoleLeaderFixture) routing(t *testing.T, node string) *consoleLeaderRouting {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"local_node": node, "candidates": []consoleLeaderCandidate{{Node: "a", LeaderURL: f.ca.URL + "/leader", TLSName: "cp-a.example", ConsoleOrigin: "https://console-a.example"}, {Node: "b", LeaderURL: f.cb.URL + "/leader", TLSName: "cp-b.example", ConsoleOrigin: "https://console-b.example"}}})
	routing, err := newConsoleLeaderRouting(string(raw), f.trust)
	if err != nil {
		t.Fatal(err)
	}
	return routing
}
func consoleNavRequest(method, raw string) *http.Request {
	r := httptest.NewRequest(method, raw, nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Cookie", "admin_session=source-only")
	r.Header.Set("Authorization", "Bearer source-only")
	return r
}

func TestConsoleNavigationMovesToConfirmedActiveCP(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	routing := f.routing(t, "b")
	calls := 0
	handler := securityHeaders(routing.navigation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; io.WriteString(w, "original handler") })))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, consoleNavRequest("GET", "https://console-b.example/console.html"))
	if w.Code != 302 || w.Header().Get("Location") != "https://console-a.example/console.html?console_handoff=1#" || calls != 0 {
		t.Fatalf("standby did not redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("redirect caches leadership or leaks referrer")
	}
	active := f.routing(t, "a").navigation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "active handler") }))
	w = httptest.NewRecorder()
	active.ServeHTTP(w, consoleNavRequest("GET", "https://console-a.example/console.html?console_handoff=1"))
	if w.Code != 302 || w.Header().Get("Location") != "/console.html#" {
		t.Fatal("active destination did not clear the handoff marker")
	}
	w = httptest.NewRecorder()
	active.ServeHTTP(w, consoleNavRequest("GET", "https://console-a.example/console.html"))
	if w.Code != 200 || w.Body.String() != "active handler" {
		t.Fatal("active destination did not serve normally")
	}
	// A leader-aware L4 may deliver any Console alias to the active backend.
	// Its own public entrance can be down even though this path is healthy.
	for _, host := range []string{"console-a.example", "console-b.example", "console-c.example", "console.example"} {
		for _, method := range []string{"GET", "HEAD"} {
			for _, path := range []string{"/", "/index.html", "/console.html"} {
				w = httptest.NewRecorder()
				active.ServeHTTP(w, consoleNavRequest(method, "https://"+host+path))
				if w.Code != 200 || w.Header().Get("Location") != "" {
					t.Fatalf("active backend moved a reachable entrance: %s %s%s: %d %s", method, host, path, w.Code, w.Header().Get("Location"))
				}
				w = httptest.NewRecorder()
				active.ServeHTTP(w, consoleNavRequest(method, "https://"+host+path+"?console_handoff=1"))
				if w.Code != 302 || w.Header().Get("Location") != path+"#" {
					t.Fatalf("handoff marker left its reachable entrance: %s%s: %d %s", host, path, w.Code, w.Header().Get("Location"))
				}
			}
		}
	}
}

func TestConsoleNavigationNeverReplaysWritesCredentialsOrAssets(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	handler := f.routing(t, "b").navigation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct{ method, path, accept string }{{"POST", "/console.html", "text/html"}, {"GET", "/?activate=private-token", "text/html"}, {"GET", "/admin/oidc/callback?code=secret", "text/html"}, {"GET", "/admin/session", "application/json"}, {"POST", "/control/admin/tenant", "application/json"}, {"GET", "/app.js", "text/javascript"}, {"GET", "/ready", "text/html"}, {"GET", "/console.html", "application/json"}} {
		r := consoleNavRequest(tc.method, "https://console-b.example"+tc.path)
		r.Header.Set("Accept", tc.accept)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 204 || w.Header().Get("Location") != "" {
			t.Fatalf("moved original request: %s %s", tc.method, tc.path)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("non-navigation requests started CP selection")
	}
	// A query cannot choose a destination; credential-bearing query is not moved.
	r := consoleNavRequest("GET", "https://console-b.example/?next=https://evil.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Header().Get("Location") != "" {
		t.Fatal("query-controlled redirect")
	}
}

func TestConsoleNavigationRejectsAbsentAmbiguousAndStaleLeadership(t *testing.T) {
	for _, mode := range []string{"none", "two", "stale-hop", "shared-origin"} {
		t.Run(mode, func(t *testing.T) {
			f := newConsoleLeaderFixture(t)
			routing := f.routing(t, "b")
			f.a.Store(mode != "none")
			f.b.Store(mode == "two")
			raw := "https://console-b.example/console.html"
			if mode == "stale-hop" {
				raw += "?console_handoff=1"
			}
			if mode == "shared-origin" {
				routing.Candidates[0].ConsoleOrigin = "https://console-b.example"
			}
			w := httptest.NewRecorder()
			r := consoleNavRequest("GET", raw)
			r.Header.Set("Accept-Language", "ja")
			routing.navigation(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unconfirmed management handler reached") })).ServeHTTP(w, r)
			if w.Code != 503 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "再試行する") || strings.Contains(w.Body.String(), "source-only") {
				t.Fatal("unconfirmed leadership looped or leaked")
			}
		})
	}
}

func TestConsoleLeaderNavigationSharesProbesAndTracksPromotion(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	p := f.routing(t, "b")
	now := time.Now()
	p.now = func() time.Time { return now }
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if p.leader() == nil {
				t.Error("healthy leader not found")
			}
		}()
	}
	group.Wait()
	if f.calls.Load() != 2 {
		t.Fatalf("navigation burst issued %d probes", f.calls.Load())
	}
	f.a.Store(false)
	f.b.Store(true)
	now = now.Add(time.Second)
	if leader := p.leader(); leader == nil || leader.Node != "b" {
		t.Fatal("promotion did not update target")
	}
}

func TestConsoleLeaderRoutingRejectsUntrustedConfiguration(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	for _, edit := range []func(*consoleLeaderRouting){func(p *consoleLeaderRouting) { p.Candidates[0].ConsoleOrigin = "http://console-a.example" }, func(p *consoleLeaderRouting) { p.Candidates[0].ConsoleOrigin = "https://evil.example/path" }, func(p *consoleLeaderRouting) {
		p.Candidates[0].ConsoleOrigin = "https://user:password@console-a.example"
	}, func(p *consoleLeaderRouting) { p.Candidates[0].LeaderURL = "http://cp-a.example/leader" }, func(p *consoleLeaderRouting) { p.Candidates[0].LeaderURL += "?token=secret" }, func(p *consoleLeaderRouting) { p.Candidates[0].TLSName = "*.example" }, func(p *consoleLeaderRouting) { p.LocalNode = "missing" }, func(p *consoleLeaderRouting) { p.Candidates[1].Node = "a" }} {
		p := f.routing(t, "a")
		edit(p)
		raw, _ := json.Marshal(p)
		if _, err := newConsoleLeaderRouting(string(raw), f.trust); err == nil {
			t.Fatal("invalid routing accepted")
		}
	}
	if p, err := newConsoleLeaderRouting("", nil); err != nil || p != nil {
		t.Fatal("unconfigured deployment changed")
	}
	p := f.routing(t, "a")
	raw, _ := json.Marshal(p)
	untrusted := f.trust.Clone()
	untrusted.RootCAs = x509.NewCertPool()
	rejected, err := newConsoleLeaderRouting(string(raw), untrusted)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.leader() != nil {
		t.Fatal("untrusted CP accepted as leader")
	}
}

// Real HTTPS browser-like navigation follows a temporary redirect to the active
// Console and then its auth gate. Host-only cookies are not copied to another host.
func TestConsoleLeaderRedirectRetainsDestinationAuthenticationGate(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "admin_session=destination" {
			t.Error("source session forwarded across hosts")
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	authority.TLS = f.tls.Clone()
	authority.StartTLS()
	defer authority.Close()
	validateClient := &http.Client{Transport: &http.Transport{TLSClientConfig: f.trust.Clone()}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "sign in") })
	mux.HandleFunc("/console.html", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "protected console") })
	serve := func(node string) *httptest.Server {
		s := httptest.NewUnstartedServer(securityHeaders(f.routing(t, node).navigation(authGate(authority.URL, validateClient, mux))))
		s.TLS = f.tls.Clone()
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	a, b := serve("a"), serve("b")
	addresses := map[string]string{"console-a.example": a.Listener.Addr().String(), "console-b.example": b.Listener.Addr().String()}
	transport := &http.Transport{TLSClientConfig: f.trust.Clone(), DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		return (&net.Dialer{}).DialContext(ctx, network, addresses[host])
	}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	source, _ := url.Parse("https://console-b.example")
	destination, _ := url.Parse("https://console-a.example")
	jar.SetCookies(source, []*http.Cookie{{Name: "admin_session", Value: "source", Secure: true, Path: "/"}})
	client := &http.Client{Transport: transport, Jar: jar}
	check := func(want string) {
		t.Helper()
		r, _ := http.NewRequest("GET", "https://console-b.example/console.html", nil)
		r.Header.Set("Accept", "text/html")
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.Request.URL.Host != "console-a.example" || string(data) != want {
			t.Fatalf("destination gate: %s %q", res.Request.URL, string(data))
		}
	}
	check("sign in")
	jar.SetCookies(destination, []*http.Cookie{{Name: "admin_session", Value: "destination", Secure: true, Path: "/"}})
	check("protected console")
}

func TestConsoleNavigationProbeDoesNotFollowRedirectOrTrustStatusAlone(t *testing.T) {
	for _, mode := range []string{"redirect", "html", "false-leader"} {
		t.Run(mode, func(t *testing.T) {
			f := newConsoleLeaderFixture(t)
			f.a.Store(false)
			var trapCalls atomic.Int32
			trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { trapCalls.Add(1); io.WriteString(w, `{"leader":true}`) }))
			defer trap.Close()
			cp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, trap.URL, http.StatusFound)
					return
				}
				if mode == "html" {
					io.WriteString(w, "sign in")
					return
				}
				io.WriteString(w, `{"leader":false}`)
			}))
			cp.TLS = f.tls.Clone()
			cp.StartTLS()
			defer cp.Close()
			p := f.routing(t, "b")
			p.Candidates[0].LeaderURL = cp.URL + "/leader"
			if p.leader() != nil || trapCalls.Load() != 0 {
				t.Fatal("probe accepted a redirect or non-leader 200")
			}
		})
	}
}
