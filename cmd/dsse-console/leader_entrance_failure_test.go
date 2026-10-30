package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Model the L4's TCP passthrough: the browser's original TLS name, Host and
// host-only cookies reach the Console on the active CP. No HTTP headers are
// rewritten by this entrance. Closing it must leave the CP/backend alive.
func consoleTestEntrance(t *testing.T, backend string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	accepted := make(chan struct{})
	var connections sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer incoming.Close()
				upstream, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", backend)
				if err != nil {
					return
				}
				defer upstream.Close()
				stop := context.AfterFunc(ctx, func() { incoming.Close(); upstream.Close() })
				defer stop()
				sent := make(chan struct{})
				go func() { io.Copy(upstream, incoming); upstream.Close(); close(sent) }()
				io.Copy(incoming, upstream)
				incoming.Close()
				<-sent
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); cancel(); <-accepted; connections.Wait() })
	return listener
}

func TestConsoleSurvivingEntranceKeepsSameOriginAuthenticationAndWrites(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	var writes atomic.Int32
	// This authority fixture checks Console proxy/gate behavior; it does not
	// replace the CP's own authentication, CSRF or grant-revocation tests.
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/admin/login/test":
			http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "fixture-session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			w.WriteHeader(http.StatusNoContent)
		case r.Method == "GET" && r.URL.Path == "/admin/session":
			if r.Header.Get("Cookie") != "admin_session=fixture-session" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == "POST" && r.URL.Path == "/admin/grants/test/revoke":
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("Cookie") != "admin_session=fixture-session" || r.Header.Get("X-CSRF-Token") != "fixture-csrf" || string(body) != `{"reason":"test"}` || r.Header.Get("Origin") == "" {
				t.Error("management write lost its same-origin credentials or body")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	authority.TLS = f.tls.Clone()
	authority.StartTLS()
	defer authority.Close()
	validateClient := &http.Client{Transport: &http.Transport{TLSClientConfig: f.trust.Clone()}}
	defer validateClient.CloseIdleConnections()
	mux := http.NewServeMux()
	proxy := newReverseProxy(authority.URL, f.trust.Clone())
	mux.Handle("/admin/", proxy)
	mux.Handle("/control/", http.StripPrefix("/control", proxy))
	mux.Handle("/", authGate(authority.URL+"/admin/session", validateClient, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/console.html" {
			io.WriteString(w, "protected console")
			return
		}
		io.WriteString(w, "sign in")
	})))
	console := httptest.NewUnstartedServer(securityHeaders(withoutFleetConfigurationProxy(f.routing(t, "a").navigation(mux))))
	console.TLS = f.tls.Clone()
	console.StartTLS()
	defer console.Close()
	entranceA := consoleTestEntrance(t, console.Listener.Addr().String())
	entranceB := consoleTestEntrance(t, console.Listener.Addr().String())
	entranceC := consoleTestEntrance(t, console.Listener.Addr().String())
	addresses := map[string]string{"console-a.example": entranceA.Addr().String(), "console-b.example": entranceB.Addr().String(), "console-c.example": entranceC.Addr().String(), "console.example": entranceB.Addr().String()}
	entranceA.Close() // The active CP and Console still run; only its public entrance is gone.
	var stoppedEntranceDials atomic.Int32
	transport := &http.Transport{TLSClientConfig: f.trust.Clone(), DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "console-a.example" {
			stoppedEntranceDials.Add(1)
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addresses[host])
	}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
	for _, host := range []string{"console-b.example", "console-c.example", "console.example"} {
		t.Run(host, func(t *testing.T) {
			origin := "https://" + host
			request := func(method, path, body, wantBody string, wantStatus int) {
				t.Helper()
				r, _ := http.NewRequest(method, origin+path, strings.NewReader(body))
				r.Header.Set("Accept", "text/html")
				if method == "POST" {
					r.Header.Set("Origin", origin)
					r.Header.Set("X-CSRF-Token", "fixture-csrf")
					r.Header.Set("Content-Type", "application/json")
				}
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				data, _ := io.ReadAll(res.Body)
				if res.Request.URL.Host != host || res.StatusCode != wantStatus || string(data) != wantBody {
					t.Fatalf("reachable entrance changed: %s %s %d %q", method, res.Request.URL, res.StatusCode, data)
				}
			}
			// A different entrance's host-only cookie cannot sign this one in.
			request("GET", "/console.html", "", "sign in", http.StatusOK)
			request("POST", "/admin/login/test", `{}`, "", http.StatusNoContent)
			request("GET", "/console.html", "", "protected console", http.StatusOK)
			before := writes.Load()
			request("POST", "/control/admin/grants/test/revoke", `{"reason":"test"}`, "", http.StatusNoContent)
			if writes.Load() != before+1 {
				t.Fatal("write was lost or replayed")
			}
		})
	}
	if stoppedEntranceDials.Load() != 0 {
		t.Fatal("a surviving entrance sent the browser to the stopped entrance")
	}
}
