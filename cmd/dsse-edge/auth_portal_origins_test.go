package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestBrokerOriginsAreExplicitAndHostSelected(t *testing.T) {
	origins, err := configuredBrokerOrigins(serverConfig{ClientlessBaseURL: "https://PORTAL-A.example:443/", StepUpPortalOrigins: "https://portal-a.example,https://portal-b.example;https://portal-c.example:8443"})
	if err != nil || len(origins) != 3 || origins[0] != "https://portal-a.example" {
		t.Fatalf("origins: %v %v", origins, err)
	}
	for _, raw := range []string{"http://portal.example", "https://*.example", "https://portal.example/path", "https://user@portal.example", "https://portal.example?x=1"} {
		if _, err := configuredBrokerOrigins(serverConfig{ClientlessBaseURL: "https://portal-a.example", StepUpPortalOrigins: raw}); err == nil {
			t.Fatalf("invalid origin accepted: %s", raw)
		}
	}
	handlers := map[string]http.Handler{}
	for _, origin := range origins {
		handlers[origin] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, origin) })
	}
	mux := http.NewServeMux()
	registerBrokerOrigins(mux, origins, handlers)
	for _, origin := range origins {
		r := httptest.NewRequest("GET", origin+"/clientless/auth/start", nil)
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != origin {
			t.Fatalf("wrong immutable origin: %d %s", w.Code, w.Body.String())
		}
	}
	for _, origin := range []string{"https://attacker.example", "https://portal-a.example:8443", "https://portal-c.example"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", origin+"/clientless/auth/callback", nil))
		if w.Code != 421 {
			t.Fatalf("unconfigured origin %s dispatched: %d", origin, w.Code)
		}
	}
}

func TestThreeRegionEdgeServesOnlyItsLocalPortal(t *testing.T) {
	config := serverConfig{ClientlessBaseURL: "https://PORTAL-B.example:443/", StepUpPortalOrigins: "https://portal-a.example,https://portal-b.example,https://portal-c.example"}
	approved, err := configuredBrokerOrigins(config)
	if err != nil {
		t.Fatal(err)
	}
	served, err := servedBrokerOrigins("three-regions-multi-edge", config, approved)
	if err != nil || len(served) != 1 || served[0] != "https://portal-b.example" {
		t.Fatalf("local Portal: %v %v", served, err)
	}
	combined, err := servedBrokerOrigins("one-region-three-nodes", config, approved)
	if err != nil || len(combined) != 3 {
		t.Fatalf("combined-node Portals: %v %v", combined, err)
	}
	if _, err := servedBrokerOrigins("three-regions-multi-edge", serverConfig{ClientlessBaseURL: "https://outside.example"}, approved); err == nil {
		t.Fatal("unapproved local Portal accepted")
	}
	if _, err := servedBrokerOrigins("three-regions-multi-edge", config, approved[:2]); err == nil {
		t.Fatal("missing foreign Portal reservation accepted")
	}
	handlers := map[string]http.Handler{served[0]: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	mux := http.NewServeMux()
	registerBrokerOriginsForProfile(mux, served, handlers, true)
	for _, origin := range approved {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", origin+"/clientless/auth/start", nil))
		want := http.StatusMisdirectedRequest
		if origin == served[0] {
			want = http.StatusNoContent
		}
		if w.Code != want {
			t.Fatalf("%s dispatched with status %d, want %d", origin, w.Code, want)
		}
	}
}

func TestForeignRegionalPortalSNIFailsClosedEvenWithBroadTransportCertificate(t *testing.T) {
	previous := stepUpPortalCert.Load()
	t.Cleanup(func() { stepUpPortalCert.Store(previous) })
	dir := t.TempDir()
	localCert, localKey := filepath.Join(dir, "local.crt"), filepath.Join(dir, "local.key")
	transportCert, transportKey := filepath.Join(dir, "transport.crt"), filepath.Join(dir, "transport.key")
	writeSelfSignedFor(t, "portal-b.example", localCert, localKey)
	writeSelfSignedFor(t, "portal-a.example", transportCert, transportKey, "portal-b.example", "portal-c.example")
	approved := []string{"https://portal-a.example", "https://portal-b.example", "https://portal-c.example"}
	configureStepUpPortalCertificatesForServedOriginsWithTrust(approved, []string{approved[1]}, localCert, localKey, "", false)
	transportPair, err := tls.LoadX509KeyPair(transportCert, transportKey)
	if err != nil {
		t.Fatal(err)
	}
	get := transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &transportPair, nil })
	if cert, err := get(&tls.ClientHelloInfo{ServerName: "portal-b.example"}); err != nil || cert == nil || stepUpPortalCertificateFor("portal-b.example") == nil {
		t.Fatalf("local Portal rejected: %v", err)
	}
	for _, name := range []string{"portal-a.example", "portal-c.example"} {
		if browserPortalConfigFor(&tls.Config{}, &tls.ClientHelloInfo{ServerName: name}) != nil {
			t.Fatalf("foreign Portal %s received browser lane", name)
		}
		if _, err := get(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("foreign Portal %s fell through to broad transport certificate", name)
		}
	}
}

func TestAllPortalNamesUseBrowserTLSWithoutChangingAgentAdmission(t *testing.T) {
	previous := stepUpPortalCert.Load()
	t.Cleanup(func() { stepUpPortalCert.Store(previous) })
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "portal.crt"), filepath.Join(dir, "portal.key")
	names := []string{"portal-a.example", "portal-b.example", "portal-c.example"}
	writeSelfSignedFor(t, names[0], certPath, keyPath, names[1:]...)
	origins := []string{}
	for _, name := range names {
		origins = append(origins, "https://"+name)
	}
	configureStepUpPortalCertificatesForProfile(origins, certPath, keyPath, false)
	base := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, VerifyConnection: func(tls.ConnectionState) error { return fmt.Errorf("endpoint identity required") }}
	for _, name := range names {
		browser := browserPortalConfigFor(base, &tls.ClientHelloInfo{ServerName: name})
		if browser == nil || browser.ClientAuth != tls.NoClientCert {
			t.Fatalf("browser asks for endpoint key: %s", name)
		}
		leaf, err := x509.ParseCertificate(browser.Certificates[0].Certificate[0])
		if err != nil || leaf.VerifyHostname(name) != nil {
			t.Fatal("browser SAN missing")
		}
		// The HTTP lane must still reject a different Host under this TLS SNI.
		r := httptest.NewRequest("GET", "https://portal-a.example/clientless/auth/start", nil)
		r.TLS = &tls.ConnectionState{ServerName: name}
		r.Host = "attacker.example"
		w := httptest.NewRecorder()
		if !serveBrowserPortalIfNamed(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("mismatched Host dispatched") })) || w.Code != 421 {
			t.Fatal("Host/SNI boundary lost")
		}
	}
	if browserPortalConfigFor(base, &tls.ClientHelloInfo{ServerName: "agents.example"}) != nil || base.ClientAuth != tls.RequireAndVerifyClientCert || base.VerifyConnection == nil {
		t.Fatal("agent TLS weakened")
	}
	// Perform real TLS and HTTP exchanges for every declared SNI. No endpoint
	// certificate is supplied; adjacent agent admission remains unchanged.
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	base.Certificates = []tls.Certificate{pair}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { return browserPortalConfigFor(base, hello), nil }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !serveBrowserPortalIfNamed(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })) {
			http.Error(w, "endpoint required", 401)
		}
	}))
	srv.TLS = base
	srv.StartTLS()
	defer srv.Close()
	for _, name := range names {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name}}
		client := &http.Client{Transport: tr}
		for _, tc := range []struct {
			path   string
			status int
		}{{"/clientless/auth/start", 204}, {"/admin/grants", 404}, {"/steer/mux", 404}} {
			req, _ := http.NewRequest("GET", srv.URL+tc.path, nil)
			req.Host = name
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != tc.status {
				t.Fatalf("%s %s: %d", name, tc.path, res.StatusCode)
			}
		}
		tr.CloseIdleConnections()
	}
	// An incomplete SAN pair reserves/refuses the uncovered names, even in lab mode.
	writeSelfSignedFor(t, names[0], certPath, keyPath)
	configureStepUpPortalCertificatesForProfile(origins, certPath, keyPath, false)
	if stepUpPortalCertificateFor(names[0]) == nil || stepUpPortalCertificateFor(names[1]) != nil || stepUpPortalCertificateRefusal(names[1]) == nil {
		t.Fatal("incomplete SAN pair silently accepted")
	}
}

func TestThreePortalOriginsRecoverSealedCeremonies(t *testing.T) {
	for _, origin := range []string{"https://portal-a.example", "https://portal-b.example", "https://portal-c.example"} {
		t.Run(origin, func(t *testing.T) { testSealedCeremonySurvivesPortalLoss(t, nil, origin) })
	}
}

func TestSharedFleetStartRequiresRecoveryAndVerifiedEndpoint(t *testing.T) {
	b, gate := ceremonyFixture(t)
	b.requireFleetRecovery = true
	link := authTestSignedLink(gate, gate.stepUpURLFor("app:22", "corp", "", "device", "tenant"))
	w := httptest.NewRecorder()
	b.handleStart(w, httptest.NewRequest("GET", link, nil))
	if w.Code != 503 {
		t.Fatalf("unrecoverable ceremony started: %d", w.Code)
	}
	b.recoverySharedKey = true
	w = httptest.NewRecorder()
	b.handleStart(w, httptest.NewRequest("GET", b.selfBaseURL+"/clientless/auth/start?return_to=app:22", nil))
	if w.Code != 401 {
		t.Fatalf("anonymous process-local ceremony accepted behind shared pool: %d", w.Code)
	}
	w = httptest.NewRecorder()
	b.handleStart(w, httptest.NewRequest("GET", link, nil))
	if w.Code != 200 {
		t.Fatalf("ready fleet cannot confirm destination: %d", w.Code)
	}
}
