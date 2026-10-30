package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/outboundtls"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/upstreamtrust"
)

type upstreamTLSModeSnapshotStore struct {
	policy.RuntimeStore
	mode      string
	snapshots int
}

func (s *upstreamTLSModeSnapshotStore) SnapshotTenantConfig(string) policy.TenantConfigBundle {
	s.snapshots++
	return policy.TenantConfigBundle{UpstreamTLSMode: s.mode}
}

type upstreamTLSModeFastStore struct{ upstreamTLSModeSnapshotStore }

func (s *upstreamTLSModeFastStore) UpstreamTLSModeFor(string) string { return s.mode }

func TestUpstreamTLSModeRuntimeStoreFastAndFallbackReads(t *testing.T) {
	// Strict is the choice that differs from the default, so it is the one
	// that must survive both read paths.
	fallback := &upstreamTLSModeSnapshotStore{mode: upstreamTLSStrict}
	fast := &upstreamTLSModeFastStore{upstreamTLSModeSnapshotStore{mode: upstreamTLSStrict}}
	for _, store := range []policy.RuntimeStore{fallback, fast} {
		if upstreamTLSModeForTenant(store, "tenant-a") != upstreamTLSStrict {
			t.Fatal("lost distributed tenant mode")
		}
	}
	if fallback.snapshots != 1 || fast.snapshots != 0 {
		t.Fatal("getter copied unrelated tenant configuration or fallback was bypassed")
	}
	if upstreamTLSModeForTenant(nil, "tenant-a") != upstreamTLSBrowserCompatible || upstreamTLSModeForTenant(fast, "") != upstreamTLSBrowserCompatible {
		t.Fatal("missing policy or tenant did not get the browser-compatible default")
	}
	// Only an explicit strict choice narrows; an unset or unknown value is not one.
	for _, mode := range []string{"", "unknown"} {
		fast.mode = mode
		if upstreamTLSModeForTenant(fast, "tenant-a") != upstreamTLSBrowserCompatible {
			t.Fatalf("mode %q did not resolve to the default", mode)
		}
	}
}

func upstreamTLSFixture(t *testing.T, suites []uint16, maxVersion uint16, http2 bool) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	return upstreamTLSFixtureWithExpiry(t, suites, maxVersion, http2, time.Now().Add(time.Hour))
}

func upstreamTLSFixtureWithExpiry(t *testing.T, suites []uint16, maxVersion uint16, http2 bool, notAfter time.Time) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream TLS test"},
		DNSNames: []string{"origin.test", "init.ess.apple.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "accepted")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.EnableHTTP2 = http2
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: maxVersion, CipherSuites: suites,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, pool
}

func upstreamTLSFixtureTransport(server *httptest.Server, roots *x509.CertPool) *http.Transport {
	return &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
}

func upstreamTLSRequest(t *testing.T, transport http.RoundTripper, host string) (*http.Response, error) {
	t.Helper()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://" + host + "/")
	if response != nil {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	return response, err
}

// A site that accepts only RSA key exchange opens by default, as it does in
// Chrome; only an organization that chose strict is refused. Each of the four
// RSA suites Chrome offers is exercised on its own.
func TestUpstreamTLSModeStaticRSAOnlySiteOpensUnlessStrictWasChosen(t *testing.T) {
	for _, cipher := range chromeStaticRSASuites {
		t.Run(tls.CipherSuiteName(cipher), func(t *testing.T) {
			server, pool := upstreamTLSFixture(t, []uint16{cipher}, tls.VersionTLS12, false)
			base := upstreamTLSFixtureTransport(server, pool)
			for _, tc := range []struct {
				tenant, mode string
				success      bool
			}{
				{"a", "", true}, {"a", upstreamTLSBrowserCompatible, true},
				{"b", upstreamTLSStrict, false}, {"a", upstreamTLSStrict, false},
				{"a", "unrecognized", true}, {"", "", true}, {"", upstreamTLSBrowserCompatible, true},
				{"a", "", true},
			} {
				adapted := upstreamTransportForTenantTLSMode(base, tc.tenant, tc.mode)
				// Keep the same AIA layer as the real handler; it must not disable
				// either the compatibility setting or certificate verification.
				wrapped := outboundtls.WrapRoundTripper(adapted)
				if closer, ok := wrapped.(interface{ CloseIdleConnections() }); ok {
					t.Cleanup(closer.CloseIdleConnections)
				}
				resp, err := upstreamTLSRequest(t, wrapped, "origin.test")
				if (err == nil) != tc.success {
					t.Fatalf("tenant=%s mode=%s success=%v err=%v", tc.tenant, tc.mode, tc.success, err)
				}
				if tc.success && (resp.TLS == nil || resp.TLS.Version != tls.VersionTLS12 || resp.TLS.CipherSuite != cipher) {
					t.Fatalf("unexpected negotiated TLS: %+v", resp.TLS)
				}
			}
		})
	}
}

func TestUpstreamTLSModePreservesActualDefaultClientHelloSuites(t *testing.T) {
	server, pool := upstreamTLSFixture(t, nil, tls.VersionTLS12, false)
	hellos := make(chan []uint16, 2)
	server.TLS.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos <- slices.Clone(h.CipherSuites)
		return nil, nil
	}
	base := upstreamTLSFixtureTransport(server, pool)
	base.TLSClientConfig.MaxVersion = tls.VersionTLS12
	for _, mode := range []string{upstreamTLSStrict, upstreamTLSBrowserCompatible} {
		transport := upstreamTransportForTenantTLSMode(base, "hello", mode).(*http.Transport)
		t.Cleanup(transport.CloseIdleConnections)
		if _, err := upstreamTLSRequest(t, transport, "origin.test"); err != nil {
			t.Fatal(err)
		}
	}
	strict, compatible := <-hellos, <-hellos
	want := append(slices.Clone(strict), chromeStaticRSASuites...)
	slices.Sort(want)
	slices.Sort(compatible)
	if !slices.Equal(want, compatible) {
		t.Fatalf("compatibility changed default suites beyond Chrome's four RSA suites: strict=%v compatible=%v", strict, compatible)
	}
	// Every TLS 1.2 suite in Chrome 156's ClientHello, captured 2026-10-29
	// (TLS 1.3 suites are not configurable in Go and are always offered).
	chrome156 := []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	for _, suite := range chrome156 {
		if !slices.Contains(compatible, suite) {
			t.Fatalf("Chrome offers %s and the default does not", tls.CipherSuiteName(suite))
		}
	}
	for _, suite := range []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA} {
		if !slices.Contains(compatible, suite) {
			t.Fatalf("lost baseline ECDHE CBC suite %s", tls.CipherSuiteName(suite))
		}
	}
	// Chrome does not offer these either.
	for _, suite := range []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256} {
		if slices.Contains(compatible, suite) {
			t.Fatalf("unexpected compatibility suite %s", tls.CipherSuiteName(suite))
		}
	}
}

func TestUpstreamTLSModePreservesVerificationAndCustomConstraints(t *testing.T) {
	server, pool := upstreamTLSFixture(t, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, tls.VersionTLS12, false)
	for _, tc := range []struct {
		name, host string
		configure  func(*tls.Config)
	}{
		{"unknown authority", "origin.test", func(c *tls.Config) { c.RootCAs = x509.NewCertPool() }},
		{"wrong hostname", "other.test", func(*tls.Config) {}},
		{"explicit cipher constraint", "origin.test", func(c *tls.Config) { c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} }},
		{"TLS13 minimum", "origin.test", func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 }},
		{"custom verifier", "origin.test", func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { return errors.New("custom verification refused") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := upstreamTLSFixtureTransport(server, pool)
			tc.configure(base.TLSClientConfig)
			transport := upstreamTransportForTenantTLSMode(base, "verification", upstreamTLSBrowserCompatible).(*http.Transport)
			t.Cleanup(transport.CloseIdleConnections)
			if transport.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("compatibility disabled TLS verification")
			}
			if _, err := upstreamTLSRequest(t, outboundtls.WrapRoundTripper(transport), tc.host); err == nil {
				t.Fatal("compatibility ignored trust/name/custom TLS restriction")
			}
		})
	}
	t.Run("expired certificate", func(t *testing.T) {
		expired, roots := upstreamTLSFixtureWithExpiry(t, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, tls.VersionTLS12, false, time.Now().Add(-time.Minute))
		base := upstreamTLSFixtureTransport(expired, roots)
		transport := upstreamTransportForTenantTLSMode(base, "expired", upstreamTLSBrowserCompatible).(*http.Transport)
		t.Cleanup(transport.CloseIdleConnections)
		_, err := upstreamTLSRequest(t, outboundtls.WrapRoundTripper(transport), "origin.test")
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
			t.Fatalf("compatibility/AIA did not reject actual expired certificate: %v", err)
		}
	})
}

func TestUpstreamTLSModePreservesTLS13AndHTTP2(t *testing.T) {
	server, pool := upstreamTLSFixture(t, nil, tls.VersionTLS13, true)
	base := upstreamTLSFixtureTransport(server, pool)
	for _, mode := range []string{upstreamTLSStrict, upstreamTLSBrowserCompatible} {
		transport := upstreamTransportForTenantTLSMode(base, "modern", mode).(*http.Transport)
		t.Cleanup(transport.CloseIdleConnections)
		response, err := upstreamTLSRequest(t, outboundtls.WrapRoundTripper(transport), "origin.test")
		if err != nil {
			t.Fatal(err)
		}
		if response.ProtoMajor != 2 || response.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("lost TLS13/HTTP2: proto=%s TLS=%x", response.Proto, response.TLS.Version)
		}
	}
}

func TestUpstreamTLSModeSeparatesPoolsAndResumptionCaches(t *testing.T) {
	server, pool := upstreamTLSFixture(t, nil, tls.VersionTLS12, false)
	base := upstreamTLSFixtureTransport(server, pool)
	base.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	profiles := make(map[string]*http.Transport)
	for _, tc := range []struct {
		tenant, mode string
		resumed      bool
	}{
		{"a", upstreamTLSStrict, false}, {"a", upstreamTLSStrict, true},
		{"b", upstreamTLSStrict, false}, {"a", upstreamTLSBrowserCompatible, false},
		{"a", upstreamTLSStrict, true}, // Only the prior strict profile's ticket can resume.
	} {
		transport := upstreamTransportForTenantTLSMode(base, tc.tenant, tc.mode).(*http.Transport)
		t.Cleanup(transport.CloseIdleConnections)
		key := tc.tenant + "/" + tc.mode
		if previous := profiles[key]; previous != nil && transport != previous {
			t.Fatal("same tenant/mode lost its stable pool")
		}
		profiles[key] = transport
		if transport.TLSClientConfig.ClientSessionCache == base.TLSClientConfig.ClientSessionCache {
			t.Fatal("inherited shared resumption cache")
		}
		response, err := upstreamTLSRequest(t, transport, "origin.test")
		if err != nil {
			t.Fatal(err)
		}
		if response.TLS.DidResume != tc.resumed {
			t.Fatalf("tenant=%s mode=%s resumed=%v want=%v", tc.tenant, tc.mode, response.TLS.DidResume, tc.resumed)
		}
		transport.CloseIdleConnections() // Next request proves ticket, not socket, isolation.
	}
	// Another immutable base trust snapshot cannot inherit a valid ticket.
	untrusted := base.Clone()
	untrusted.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport := upstreamTransportForTenantTLSMode(untrusted, "a", upstreamTLSStrict).(*http.Transport)
	t.Cleanup(transport.CloseIdleConnections)
	if _, err := upstreamTLSRequest(t, transport, "origin.test"); err == nil {
		t.Fatal("new trust identity resumed a previously trusted session")
	}
}

func TestUpstreamTLSModeRepeatedSwitchesReuseOnlyTwoDerivedProfiles(t *testing.T) {
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), ClientSessionCache: tls.NewLRUClientSessionCache(8)}}
	profiles := make(map[http.RoundTripper]bool)
	aia := make(map[http.RoundTripper]bool)
	vendor := make(map[http.RoundTripper]bool)
	tickets := make(map[tls.ClientSessionCache]bool)
	for i := 0; i < 50; i++ {
		for _, mode := range []string{upstreamTLSStrict, upstreamTLSBrowserCompatible} {
			transport := upstreamTransportForTenantTLSMode(base, "stable-profiles", mode).(*http.Transport)
			profiles[transport] = true
			aia[outboundtls.WrapRoundTripper(transport)] = true
			vendor[upstreamtrust.ForHost(transport, "init.ess.apple.com")] = true
			tickets[transport.TLSClientConfig.ClientSessionCache] = true
		}
	}
	if len(profiles) != 2 || len(aia) != 2 || len(vendor) != 2 || len(tickets) != 2 {
		t.Fatalf("mode changes retained new profiles: base=%d AIA=%d vendor=%d tickets=%d", len(profiles), len(aia), len(vendor), len(tickets))
	}
	for profile := range profiles {
		outboundtls.CloseIdleConnectionsForTransport(profile.(*http.Transport))
		upstreamtrust.CloseIdleConnectionsForTransport(profile.(*http.Transport))
	}
}

func TestUpstreamTLSModeChangePreservesActiveDerivedResponse(t *testing.T) {
	for _, host := range []string{"origin.test", "init.ess.apple.com"} {
		t.Run(host, func(t *testing.T) {
			server, roots := upstreamTLSFixture(t, nil, tls.VersionTLS13, true)
			release := make(chan struct{})
			var released sync.Once
			unblock := func() { released.Do(func() { close(release) }) }
			defer unblock()
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "before-")
				w.(http.Flusher).Flush()
				<-release
				io.WriteString(w, "after")
			})
			base := upstreamTLSFixtureTransport(server, roots)
			var dials atomic.Int32
			dial := base.DialContext
			base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dials.Add(1)
				return dial(ctx, network, addr)
			}
			compatible := upstreamTransportForTenantTLSMode(base, "in-flight", upstreamTLSBrowserCompatible).(*http.Transport)
			wrap := func(tr *http.Transport) http.RoundTripper {
				return outboundtls.WrapRoundTripper(upstreamtrust.ForHost(tr, host))
			}
			client := &http.Client{Transport: wrap(compatible), Timeout: 5 * time.Second}
			response, err := client.Get("https://" + host + "/")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			strict := upstreamTransportForTenantTLSMode(base, "in-flight", upstreamTLSStrict).(*http.Transport)
			t.Cleanup(func() {
				outboundtls.CloseIdleConnectionsForTransport(strict)
				upstreamtrust.CloseIdleConnectionsForTransport(strict)
			})
			if strict == compatible {
				t.Fatal("strict reused compatible pool")
			}
			unblock()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "before-after" {
				t.Fatalf("mode switch interrupted active response: body=%q err=%v", body, err)
			}
			response.Body.Close()
			if _, err := upstreamTLSRequest(t, wrap(strict), host); err != nil {
				t.Fatal(err)
			}
			if dials.Load() != 2 {
				t.Fatalf("strict request reused previous mode's connection: dials=%d", dials.Load())
			}
		})
	}
}

func TestUpstreamTLSModeRetainsConnectorRoutingAndOpaqueEngines(t *testing.T) {
	server, pool := upstreamTLSFixture(t, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, tls.VersionTLS12, false)
	base := upstreamTLSFixtureTransport(server, pool)
	var brokerCalls atomic.Int32
	broker := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		brokerCalls.Add(1)
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
	})
	resolve := func(_ context.Context, _, host, _ string) (model.ConnectorRegistration, bool, error) {
		return model.ConnectorRegistration{}, host == "origin.test", nil
	}
	wrapped := edgeplane.NewConnectorOrBrokerRoundTripper(resolve, "operator", base, broker)
	for _, tc := range []struct {
		tenant, mode string
		allow        bool
	}{{"a", upstreamTLSBrowserCompatible, true}, {"b", upstreamTLSStrict, false}} {
		adapted := upstreamTransportForTenantTLSMode(wrapped, tc.tenant, tc.mode)
		scope, ok := adapted.(edgeplane.TenantConnectorTransport)
		if !ok {
			t.Fatal("lost connector transport semantics")
		}
		t.Cleanup(scope.ConnectorTransport().(*http.Transport).CloseIdleConnections)
		if _, err := upstreamTLSRequest(t, adapted, "origin.test"); (err == nil) != tc.allow {
			t.Fatalf("connector tenant=%s err=%v", tc.tenant, err)
		}
		if _, err := upstreamTLSRequest(t, adapted, "public.test"); err != nil {
			t.Fatal(err)
		}
	}
	if brokerCalls.Load() != 2 {
		t.Fatal("connector compatibility replaced public broker")
	}
	if got := upstreamTransportForTenantTLSMode(broker, "a", upstreamTLSBrowserCompatible); reflect.ValueOf(got).Pointer() != reflect.ValueOf(broker).Pointer() {
		t.Fatal("opaque transport replaced")
	}
	custom := base.Clone()
	custom.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("owned TLS engine") }
	if got := upstreamTransportForTenantTLSMode(custom, "a", upstreamTLSBrowserCompatible); got != custom {
		t.Fatal("custom TLS engine replaced")
	}
}

func TestUpstreamTLSModeDoesNotReplayPOST(t *testing.T) {
	server, pool := upstreamTLSFixture(t, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, tls.VersionTLS12, false)
	var posts atomic.Int32
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			io.Copy(io.Discard, r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		io.WriteString(w, "prime pool")
	})
	base := upstreamTLSFixtureTransport(server, pool)
	for _, mode := range []string{upstreamTLSStrict, upstreamTLSBrowserCompatible} {
		transport := upstreamTransportForTenantTLSMode(base, "post", mode).(*http.Transport)
		t.Cleanup(transport.CloseIdleConnections)
		if mode == upstreamTLSBrowserCompatible {
			if _, err := upstreamTLSRequest(t, transport, "origin.test"); err != nil {
				t.Fatal(err)
			}
		}
		request, _ := http.NewRequest(http.MethodPost, "https://origin.test/submit", strings.NewReader("payload"))
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			t.Fatal("closed origin unexpectedly succeeded")
		}
		want := int32(0)
		if mode == upstreamTLSBrowserCompatible {
			want = 1
		}
		if posts.Load() != want {
			t.Fatalf("POST was replayed or strict mode retried with compatibility: got %d want %d", posts.Load(), want)
		}
	}
}

func TestUpstreamTLSModeLogsOnlyActualStaticRSAUse(t *testing.T) {
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	response := &http.Response{TLS: &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}}
	logUpstreamTLSCompatibilityUse("tenant-a", "origin.test", upstreamTLSBrowserCompatible, response)
	if output.Len() != 0 {
		t.Fatal("logged static RSA for TLS13")
	}
	response.TLS.Version = tls.VersionTLS12
	response.TLS.CipherSuite = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	response.Request, _ = http.NewRequest(http.MethodGet, "https://user:private-password@origin.test/private-path?token=private-token", nil)
	response.Request.Header.Set("Authorization", "Bearer private-credential")
	response.Header = http.Header{"Set-Cookie": {"private-cookie"}}
	logUpstreamTLSCompatibilityUse("tenant-a", "origin.test", upstreamTLSBrowserCompatible, response)
	text := output.String()
	for _, want := range []string{`tenant="tenant-a"`, `host="origin.test"`, "cipher=TLS_RSA_WITH_AES_128_GCM_SHA256", "mode=browser_compatible"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing metadata %s: %s", want, text)
		}
	}
	for _, secret := range []string{"private-password", "private-path", "private-token", "private-credential", "private-cookie"} {
		if strings.Contains(text, secret) {
			t.Fatalf("TLS metadata log leaked %s", secret)
		}
	}
}
