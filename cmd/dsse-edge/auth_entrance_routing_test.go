package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authportal"
	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestEntrancePortalOriginsRejectAmbiguousOrUntrustedConfig(t *testing.T) {
	approved := []string{"https://portal-a.example", "https://portal-b.example"}
	for _, raw := range []string{`{}`, `[]`, `null`, `{"agents.example":"https://evil.example"}`, `{"agents.example":"http://portal-a.example"}`, `{"agents.example:443":"https://portal-a.example"}`, `{"*.example":"https://portal-a.example"}`, `{"AGENTS.example":"https://portal-a.example","agents.example":"https://portal-b.example"}`, `{"agents.example":"https://portal-a.example"} {}`, `{"agents.example":1}`} {
		if _, err := parseEntrancePortalOrigins(raw, approved); err == nil {
			t.Fatalf("accepted ambiguous mapping %s", raw)
		}
	}
	m, err := parseEntrancePortalOrigins(`{"AGENTS.example":"https://PORTAL-A.example:443/"}`, approved)
	if err != nil || m["agents.example"] != "https://portal-a.example" {
		t.Fatalf("canonical map: %v %v", m, err)
	}
	if m, err := parseEntrancePortalOrigins("", approved); err != nil || m != nil {
		t.Fatal("legacy upgrade enabled shared mapping")
	}
}

func TestApprovedAgentSNIFailoverSelectsServingRegionsPortal(t *testing.T) {
	approved := []string{"https://portal-a.example", "https://portal-b.example", "https://portal-c.example"}
	raw := `{"agents.example":"https://portal-a.example","agents-a.example":"https://portal-a.example","agents-b.example":"https://portal-b.example"}`
	mapping, err := parseEntrancePortalOrigins(raw, approved)
	if err != nil {
		t.Fatal(err)
	}
	local := localizeEntrancePortalOrigins("three-regions-multi-edge", mapping, []string{approved[1]})
	if mapping["agents-a.example"] != approved[0] {
		t.Fatal("approved mapping mutated")
	}
	for _, sni := range []string{"agents.example", "agents-a.example", "agents-b.example"} {
		if local[sni] != approved[1] {
			t.Fatalf("failover SNI %s did not select the serving Region's Portal", sni)
		}
	}
	if _, known := local["unapproved.example"]; known {
		t.Fatal("unapproved SNI accepted")
	}
	if original := localizeEntrancePortalOrigins("one-region-three-nodes", mapping, []string{approved[1]}); original["agents-a.example"] != approved[0] {
		t.Fatal("combined-node entrance semantics changed")
	}
}

func TestEntrancePortalUsesOuterTransportAndSignedOrigin(t *testing.T) {
	_, gate := ceremonyFixture(t)
	gate.brokerBaseURL = "https://stopped-c.example"
	gate.entranceOrigins = map[string]string{"agents-a.example": "https://portal-a.example", "recovery-b.example": "https://portal-b.example", "agents.example": "https://portal-b.example"}
	for name, origin := range gate.entranceOrigins {
		req := httptest.NewRequest("CONNECT", "https://unrelated-target.example:443", nil)
		req.TLS = &tls.ConnectionState{ServerName: strings.ToUpper(name)}
		req.Host = "stopped-c.example"
		req.Header.Set("X-Forwarded-Host", "stopped-c.example")
		transportIngressMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			// Interception replaces the HTTP destination; the ingress identity survives.
			r.TLS = &tls.ConnectionState{ServerName: "stopped-c.example"}
			link := gate.stepUpURLForRequest(r, "app.example:22", "device", "tenant", federatedRequirements{IdP: "corp", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession})
			parsed, err := url.Parse(link)
			if err != nil || "https://"+parsed.Host != origin || parsed.Query().Get("portal_origin") != origin+":443" {
				t.Fatal("selected processing Edge or inner destination instead of transport ingress")
			}
			if _, err := authportal.ValidateStart(link, []string{origin}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if gate.signer.signRequirements(parsed.Query()) != parsed.Query().Get("requirements_sig") {
				t.Fatal("ingress change lost the signed requirements")
			}
		})).ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, name := range []string{"", "unknown.example"} {
		r := httptest.NewRequest("GET", "https://agents-a.example/", nil)
		r.TLS = &tls.ConnectionState{ServerName: name}
		r.Header.Set("X-Forwarded-Host", "agents-a.example")
		if gate.stepUpURLForRequest(r, "app:22", "device", "tenant", federatedRequirements{}) != "" {
			t.Fatal("unknown SNI fell back to an Edge-local Portal")
		}
	}
}

func TestInterceptionRetainsIngressWithoutAcceptingClientRouteJSON(t *testing.T) {
	var route edgeplane.NetworkExtensionRuntimeCopyTCPRoute
	if err := json.Unmarshal([]byte(`{"host":"target.example","port":443,"TransportServerName":"forged.example","transport_server_name":"forged.example"}`), &route); err != nil {
		t.Fatal(err)
	}
	if route.TransportServerName != "" {
		t.Fatal("client supplied trusted transport identity")
	}
	route.TransportServerName = "agents-a.example"
	r := httptest.NewRequest("GET", "https://target.example/resource", nil)
	forward, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(r, route)
	if err != nil {
		t.Fatal(err)
	}
	if edgeplane.TransportServerNameFromContext(forward.Context()) != "agents-a.example" || !strings.Contains(forward.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader), "target.example") {
		t.Fatal("interception mixed ingress with target")
	}
}

// Construct the production HTTP server against a durable, mixed-version census.
// Its historical three-origin profile allowlist must not disable owner-pinned auth.
func TestSharedFleetRollingUpgradeKeepsOwnerPinnedAuthenticationUntilCutover(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-three-origin-list", true: "explicit-cutover"}[shared], func(t *testing.T) {
			runtime, manifest := rolloutFixture(t)
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := serverConfig{Writer: writer, Evaluator: testEvaluator(), ClientlessBaseURL: "https://portal.example", StepUpPortalOrigins: "https://portal.example,https://portal-b.example,https://portal-c.example", StepUpBindingSecret: "test-upgrade-shared-secret", GrantStorePath: filepath.Join(t.TempDir(), "grants.json"), AuthRolloutReporter: &authRolloutReporter{census: manifest, member: manifest.Members[1]}}
			if shared {
				cfg.EntrancePortalOrigins = `{"agents.example":"https://portal.example"}`
			}
			handler := newServerWithConfig(cfg)
			runtime = theAuthRollout.Load()
			if err := runtime.authority.Configure(context.Background(), 0, manifest); err != nil {
				t.Fatal(err)
			}
			registry := theIdPRegistry.Load()
			_, gate := ceremonyFixture(t)
			for _, row := range gate.registry.List("tenant") {
				if _, err := registry.Upsert(row); err != nil {
					t.Fatal(err)
				}
			}
			authTestAssign(t, registry, "tenant", "device", "user", "corp")
			gate.registry = registry
			gate.signer = newDeviceBindingSignerFromSecret(cfg.StepUpBindingSecret)
			gate.rollout = runtime
			gate.tenantID = "tenant"
			check := func(want int) {
				t.Helper()
				requirements := federatedRequirements{IdP: "corp"}
				if runtime.featureEnabled(authrollout.DeviceUserFeature) {
					requirements.OSPrincipal = testAuthPrincipal
					requirements.OSSession = testAuthSession
				}
				link := gate.stepUpURLWithRequirements("app.example:22", "device", "tenant", requirements)
				req := httptest.NewRequest("GET", link, nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != want {
					t.Fatalf("new auth = %d want %d: %s", rec.Code, want, rec.Body.String())
				}
			}
			check(map[bool]int{false: 200, true: 503}[shared]) // owner-pinned start shows destination confirmation
			features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature, authrollout.CeremonyRecoveryFeature}
			for _, m := range manifest.Members {
				if err := runtime.authority.Record(context.Background(), m.CertificateSHA256, authrollout.Report{NodeID: m.ID, Generation: manifest.Generation, Version: "next", Features: features}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := runtime.authority.Activate(context.Background(), manifest.Generation, features, time.Now()); err != nil {
				t.Fatal(err)
			}
			check(200)
		})
	}
}

// Exercise actual TLS handshakes as well as the mux path above. The HTTP Host
// deliberately differs from SNI, as it does after application interception.
func TestEntrancePortalSelectionAcrossRealTLS(t *testing.T) {
	_, gate := ceremonyFixture(t)
	gate.brokerBaseURL = "https://stopped-c.example"
	gate.entranceOrigins = map[string]string{"agents-a.example": "https://portal-a.example", "agents-b.example": "https://portal-b.example"}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ingress.crt"), filepath.Join(dir, "ingress.key")
	writeSelfSignedFor(t, "agents-a.example", certPath, keyPath, "agents-b.example")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	srv := httptest.NewUnstartedServer(transportIngressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		link := gate.stepUpURLForRequest(r, "app.example:22", "device", "tenant", federatedRequirements{IdP: "corp", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession})
		_, _ = io.WriteString(w, link)
	})))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	for name, origin := range gate.entranceOrigins {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}}
		client := &http.Client{Transport: tr}
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Host = "stopped-c.example"
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(res.Body)
		res.Body.Close()
		tr.CloseIdleConnections()
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(string(data))
		if err != nil || "https://"+u.Host != origin {
			t.Fatal("actual TLS ingress did not control signed Portal")
		}
		if _, err := authportal.ValidateStart(string(data), []string{origin}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}
