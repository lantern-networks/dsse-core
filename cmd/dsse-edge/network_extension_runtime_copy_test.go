package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	swg "github.com/lantern-networks/dsse-core/swg"

	"golang.org/x/net/http2"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestNetworkExtensionRuntimeCopyRoundTripReturnsTypedDefaultDenyForCurrentRequestSchema(t *testing.T) {
	handler := newNetworkExtensionRuntimeCopyTestHandler(t)
	body := `{
		"schema_version":"network_extension_runtime_copy_round_trip_request.v1",
		"tenant_id":"tenant_lab_001",
		"request_id":"manual-runtime-copy-check-001",
		"application_id":"default_network_extension_tunnel",
		"upstream_payload_b64":"QQ=="
	}`
	req := httptest.NewRequest(http.MethodPost, edgeplane.NetworkExtensionRuntimeCopyRoundTripPath, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	payload := assertNetworkExtensionRuntimeCopyStatus(t, rec, http.StatusBadGateway, "unknown_application_default_deny")
	if payload["schema_version"] != edgeplane.NetworkExtensionRuntimeCopyRoundTripErrorResponseSchema {
		t.Fatalf("schema_version = %v, want %s", payload["schema_version"], edgeplane.NetworkExtensionRuntimeCopyRoundTripErrorResponseSchema)
	}
	if payload["request_id"] != "manual-runtime-copy-check-001" {
		t.Fatalf("request_id = %v, want echo", payload["request_id"])
	}
	if payload["edge_runtime_copy_route_gate"] != "destination_authority_not_available_in_request_v1" {
		t.Fatalf("edge_runtime_copy_route_gate = %v, want destination authority gate", payload["edge_runtime_copy_route_gate"])
	}
	audit, ok := payload["audit"].(map[string]any)
	if !ok {
		t.Fatalf("audit = %#v, want object", payload["audit"])
	}
	if audit["metadata_only"] != true || audit["tenant_id"] != "tenant_lab_001" || audit["application_id"] != "default_network_extension_tunnel" {
		t.Fatalf("audit = %+v, want metadata-only tenant/application audit", audit)
	}
}

func TestNetworkExtensionRuntimeCopyRoundTripUsesDestinationAuthorityForTCPRoundTrip(t *testing.T) {
	downstreamPayload := []byte("edge-destination-response")
	conn := newRecordingNetworkExtensionRuntimeCopyTCPConnection(downstreamPayload)
	dialer := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	handler := edgeplane.NewNetworkExtensionRuntimeCopyRoundTripHandler(edgeplane.NetworkExtensionRuntimeCopyRoundTripHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   dialer,
		// ★ Generous ON PURPOSE. This test asserts which authority the round trip uses; the deadline is not
		// under test and must therefore be unable to fire. 100 ms was comfortable on the machine it was written
		// on and marginal on win-dev-1, which is 4-5x slower — where this family produced intermittent
		// "optional downstream timeout" failures that passed when re-run alone. A deadline that is scenery in
		// one test and the flake in another is worth making obviously large.
		Timeout: 10 * time.Second,
	})
	body := `{
		"schema_version":"network_extension_runtime_copy_round_trip_request.v1",
		"tenant_id":"tenant_lab_001",
		"request_id":"manual-runtime-copy-check-003",
		"application_id":"default_network_extension_tunnel",
		"destination_host":"www.google.com",
		"destination_port":443,
		"upstream_payload_b64":"Y2xpZW50LWhlbGxv"
	}`
	req := httptest.NewRequest(http.MethodPost, edgeplane.NetworkExtensionRuntimeCopyRoundTripPath, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
	if payload["schema_version"] != edgeplane.NetworkExtensionRuntimeCopyRoundTripResponseSchema ||
		payload["status"] != "ok" ||
		payload["category"] != "round_trip_completed" ||
		payload["edge_runtime_copy_route_gate"] != "destination_authority_round_trip_completed" {
		t.Fatalf("payload = %+v, want success round-trip response", payload)
	}
	if payload["request_id"] != "manual-runtime-copy-check-003" {
		t.Fatalf("request_id = %v, want echo", payload["request_id"])
	}
	downstream, err := decodeBase64String(payload["downstream_payload_b64"])
	if err != nil {
		t.Fatalf("downstream_payload_b64 invalid: %v", err)
	}
	if !bytes.Equal(downstream, downstreamPayload) {
		t.Fatalf("downstream = %q, want %q", downstream, downstreamPayload)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].Host != "www.google.com" || dialer.routes[0].Port != 443 {
		t.Fatalf("opened routes = %+v, want www.google.com:443", dialer.routes)
	}
	if conn.written.String() != "client-hello" {
		t.Fatalf("upstream written = %q, want client-hello", conn.written.String())
	}
}

func TestNetworkExtensionRuntimeCopySessionReusesDestinationTCPConnection(t *testing.T) {
	conn := newChunkedNetworkExtensionRuntimeCopyTCPConnection([][]byte{
		[]byte("session-response-1"),
		[]byte("session-response-2"),
	})
	dialer := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer:   dialer,
		// Generous for the same reason as above: this test is about the session's behaviour, not its deadline.
		Timeout:        10 * time.Second,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})

	openPayload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           "req_session_001",
		"operation":            "open",
		"application_id":       "default_network_extension_tunnel",
		"destination_host":     "www.google.com",
		"destination_port":     443,
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("client-hello-1")),
	})
	if openPayload["schema_version"] != edgeplane.NetworkExtensionRuntimeCopySessionResponseSchema ||
		openPayload["status"] != "ok" ||
		openPayload["category"] != "session_exchange_completed" ||
		openPayload["edge_runtime_copy_route_gate"] != "destination_authority_session_exchange_completed" {
		t.Fatalf("open payload = %+v, want session exchange success", openPayload)
	}
	if openPayload["session_closed"] != false {
		t.Fatalf("open session_closed = %v, want false", openPayload["session_closed"])
	}
	openDownstream, err := decodeBase64String(openPayload["downstream_payload_b64"])
	if err != nil || string(openDownstream) != "session-response-1" {
		t.Fatalf("open downstream = %q err=%v, want session-response-1", openDownstream, err)
	}

	exchangePayload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           "req_session_001",
		"operation":            "exchange",
		"application_id":       "default_network_extension_tunnel",
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("client-hello-2")),
	})
	exchangeDownstream, err := decodeBase64String(exchangePayload["downstream_payload_b64"])
	if err != nil || string(exchangeDownstream) != "session-response-2" {
		t.Fatalf("exchange downstream = %q err=%v, want session-response-2", exchangeDownstream, err)
	}
	if len(dialer.routes) != 1 || dialer.routes[0].Host != "www.google.com" || dialer.routes[0].Port != 443 {
		t.Fatalf("opened routes = %+v, want one www.google.com:443 dial", dialer.routes)
	}
	if got := conn.writtenPayloads(); len(got) != 2 || !bytes.Equal(got[0], []byte("client-hello-1")) || !bytes.Equal(got[1], []byte("client-hello-2")) {
		t.Fatalf("written payloads = %q, want two client chunks", got)
	}

	closePayload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version": edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":      "tenant_lab_001",
		"request_id":     "req_session_001",
		"operation":      "close",
		"application_id": "default_network_extension_tunnel",
	})
	if closePayload["category"] != "session_closed" || closePayload["session_closed"] != true {
		t.Fatalf("close payload = %+v, want closed", closePayload)
	}
	if !conn.closed {
		t.Fatalf("session TCP connection was not closed")
	}
}

func TestNetworkExtensionLabTLSInterceptionIssuesLeafCertificateForMatchedHost(t *testing.T) {
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"example.com"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	if interception == nil {
		t.Fatal("interception = nil, want configured lab TLS interception")
	}
	if bytes.Contains(interception.RootCertificatePEM(), []byte("PRIVATE KEY")) {
		t.Fatal("root certificate PEM unexpectedly contains private key material")
	}
	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "example.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "example.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("peer certificates empty")
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("leaf CommonName = %q, want example.com", leaf.Subject.CommonName)
	}
	if leaf.Issuer.CommonName != edgeplane.NetworkExtensionLabTLSRootCommonName {
		t.Fatalf("leaf issuer = %q, want %q", leaf.Issuer.CommonName, edgeplane.NetworkExtensionLabTLSRootCommonName)
	}
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("client write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Dsse-Lab-TLS-Interception") != "observed" {
		t.Fatalf("lab TLS header = %q, want observed", resp.Header.Get("X-Dsse-Lab-TLS-Interception"))
	}
}

func TestNetworkExtensionLabTLSInterceptionReusesPersistentRootMaterial(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "lantern_dsse_interception_root_ca.pem")
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	first, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, func() time.Time {
		return certNow
	}, certPath)
	if err != nil {
		t.Fatalf("first persistent root interception returned error: %v", err)
	}
	second, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, func() time.Time {
		return certNow.Add(time.Hour)
	}, certPath)
	if err != nil {
		t.Fatalf("second persistent root interception returned error: %v", err)
	}
	if !bytes.Equal(first.RootCertificatePEM(), second.RootCertificatePEM()) {
		t.Fatal("persistent root certificate was regenerated, want reused")
	}
	keyPath := edgeplane.NetworkExtensionLabTLSRootKeyPath(certPath)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("persistent root key missing: %v", err)
	}
	// The rest of this test is platform-neutral; only the mode assertion is not. Windows has no POSIX
	// permission bits and reports 0666 for a file written 0600, so asserting the mode there tests the
	// filesystem's answer rather than what this code did.
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("persistent root key mode = %o, want 0600", got)
		}
	}
}

func TestNetworkExtensionLabTLSInterceptionAcceptsPersistentRootDirectoryPath(t *testing.T) {
	rootDir := t.TempDir()
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, func() time.Time {
		return time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	}, rootDir)
	if err != nil {
		t.Fatalf("persistent root interception returned error: %v", err)
	}
	if interception == nil {
		t.Fatal("interception = nil, want configured lab TLS interception")
	}
	certPath := filepath.Join(rootDir, edgeplane.NetworkExtensionLabTLSRootCertFilename)
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("persistent root cert missing at default directory path: %v", err)
	}
	if _, err := os.Stat(edgeplane.NetworkExtensionLabTLSRootKeyPath(certPath)); err != nil {
		t.Fatalf("persistent root key missing at default directory path: %v", err)
	}
}

func TestNetworkExtensionLabTLSInterceptionRotatesIncompletePersistentRootMaterial(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "lantern_dsse_interception_root_ca.pem")
	material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(func() time.Time {
		return time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("generate root material: %v", err)
	}
	if err := os.WriteFile(certPath, material.CertPEM, 0600); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatalf("persistent root interception returned error: %v", err)
	}
	if bytes.Equal(interception.RootCertificatePEM(), material.CertPEM) {
		t.Fatal("incomplete persistent root certificate was reused, want rotated material")
	}
	if _, err := os.Stat(edgeplane.NetworkExtensionLabTLSRootKeyPath(certPath)); err != nil {
		t.Fatalf("rotated persistent root key missing: %v", err)
	}
}

func TestNetworkExtensionLabTLSInterceptionRotatesPersistentRootNearExpiry(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "lantern_dsse_interception_root_ca.pem")
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	first, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, func() time.Time {
		return certNow
	}, certPath)
	if err != nil {
		t.Fatalf("first persistent root interception returned error: %v", err)
	}
	second, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, func() time.Time {
		return certNow.Add(edgeplane.NetworkExtensionLabTLSRootValidity - edgeplane.NetworkExtensionLabTLSRootRotateBefore + time.Second)
	}, certPath)
	if err != nil {
		t.Fatalf("rotated persistent root interception returned error: %v", err)
	}
	if bytes.Equal(first.RootCertificatePEM(), second.RootCertificatePEM()) {
		t.Fatal("persistent root certificate was reused near expiry, want rotation")
	}
}

func TestNetworkExtensionLabTLSInterceptionRejectsBroadPersistentRootKeyPermissions(t *testing.T) {
	// os.Chmod cannot widen a file in a way Windows reports back, so the guard has nothing to detect there.
	// Worth stating plainly: before the guard learned to skip Windows it rejected EVERY key on that platform
	// (0600 reads back as 0666), so this test passed there while proving nothing — a false green that only
	// became visible once the guard stopped firing on files that were never exposed.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	certPath := filepath.Join(t.TempDir(), "lantern_dsse_interception_root_ca.pem")
	material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(func() time.Time {
		return time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("generate root material: %v", err)
	}
	if err := edgeplane.WriteNetworkExtensionLabTLSPersistentRootMaterial(certPath, material); err != nil {
		t.Fatalf("write persistent material: %v", err)
	}
	keyPath := edgeplane.NetworkExtensionLabTLSRootKeyPath(certPath)
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("chmod key fixture: %v", err)
	}
	_, err = edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err == nil || !strings.Contains(err.Error(), "group/world") {
		t.Fatalf("error = %v, want broad key permission rejection", err)
	}
}

func TestNetworkExtensionLabTLSInterceptionForwardsDecryptedHTTPRequestThroughSWGRewrite(t *testing.T) {
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	operatorConfigPath := t.TempDir() + "/operator_config.json"
	if err := os.WriteFile(operatorConfigPath, []byte(`{
  "schema_version": "swg_tenant_restriction_operator_config.v1",
  "status": "active",
  "tenant_id": "tenant_swg_lab",
  "header_values": [
    {
      "ref": "operator_config_ref:google_workspace_allowed_domains",
      "tenant_id": "tenant_swg_lab",
      "saas_application_id": "saas_google_workspace",
      "provider": "google_workspace",
      "header_name": "X-GoogApps-Allowed-Domains",
      "header_value_kind": "configured_allowed_domains",
      "value": "allowed.example",
      "status": "active",
      "metadata": {
        "operator_managed": true,
        "operator_config_value_secret": false,
        "captured_secret_material_committed": false,
        "report_value_material_logged": false
      }
    }
  ],
  "metadata": {
    "designated_operator_config_file": true
  }
}`), 0600); err != nil {
		t.Fatalf("write operator config: %v", err)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true,
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	transport := &recordingHTTPRoundTripper{
		status: http.StatusAccepted,
		body:   "forward-ok",
	}
	evaluator := decision.Evaluator{
		Policies:      policies,
		PolicyBundle:  bundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-001",
	}
	inspectionEvents := newInspectionEventStore()
	interception.SetHTTPHandler(newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator:        evaluator,
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		ProxyClient:      &http.Client{Transport: transport},
		SWGRuntime:       swgRuntime,
		DecisionStore:    newAccessDecisionStore(),
		InspectionEvents: inspectionEvents,
		LabMode:          true,
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if _, err := client.Write([]byte("GET /ServiceLogin?continue=mail HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("client write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || string(body) != "forward-ok" {
		t.Fatalf("response status/body = %d/%q, want 202/forward-ok", resp.StatusCode, body)
	}
	if transport.request == nil {
		t.Fatal("upstream request was not observed")
	}
	if got := transport.request.URL.String(); got != "https://accounts.google.com/ServiceLogin?continue=mail" {
		t.Fatalf("upstream URL = %q, want decrypted HTTPS target URL", got)
	}
	if got := transport.request.Header.Get("X-GoogApps-Allowed-Domains"); got != "allowed.example" {
		t.Fatalf("Google tenant restriction header = %q, want configured value", got)
	}
	if got := transport.request.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader); got != "" {
		t.Fatalf("SWG target control header leaked upstream: %q", got)
	}
	if got := transport.request.Header.Get(edgeplane.EdgeSWGHTTPEgressNERuntimeHeader); got != "" {
		t.Fatalf("Network Extension runtime control header leaked upstream: %q", got)
	}
	if got := transport.request.Header.Get(connectorSecretHeader); got != "" {
		t.Fatalf("connector secret control header leaked upstream: %q", got)
	}
	events := inspectionEvents.ListByTenant("tenant_swg_lab")
	if len(events) != 1 {
		t.Fatalf("inspection event count = %d, want 1", len(events))
	}
	if !swg.MetadataBool(events[0].Metadata, "runtime_header_injection_observed") {
		t.Fatalf("inspection metadata runtime_header_injection_observed = false, want true: %#v", events[0].Metadata)
	}
	if !swg.MetadataBool(events[0].Metadata, "network_extension_runtime_used") {
		t.Fatalf("inspection metadata network_extension_runtime_used = false, want true: %#v", events[0].Metadata)
	}
	status := swg.EdgeSWGTLSReadinessStatusFor(evaluator, swgRuntime, inspectionEvents, edgeplane.EdgeSWGHTTPEgressPath)
	if !status.RuntimeHeaderInjectionObserved || !status.NetworkExtensionRuntimeUsed {
		t.Fatalf("readiness runtime flags header=%v network_extension=%v, want both true", status.RuntimeHeaderInjectionObserved, status.NetworkExtensionRuntimeUsed)
	}
}

// A regression guard that also reproduces the original failure. A Google sign-in POST carries a long encoded
// URI containing signed continuation tokens. If interception and forwarding change even one byte of that URI,
// the signature check fails and Google answers 400 — which is what made the form's "next" do nothing, one
// layer up. This asserts that the target URL serve builds still matches the original request-URI exactly,
// after being re-parsed the same way newSWGHTTPEgressUpstreamRequest re-parses it.
func TestNetworkExtensionLabTLSTargetURLPreservesEncodedSigninRequestURI(t *testing.T) {
	rawRequestURI := "/v3/signin/_/AccountsSignInUi/data/batchexecute?rpcids=V1UmUe&source-path=%2Fsignin%2Fv2%2Fidentifier&f.sid=-1234567890&bl=boq_identityfrontend&hl=ja&TL=AaBbCc_-.~%2Bdd%3Dee&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&dsh=S-12345678%3A9012&_reqid=98765&rt=c"
	raw := "POST " + rawRequestURI + " HTTP/1.1\r\nHost: accounts.google.co.jp\r\nContent-Length: 0\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest returned error: %v", err)
	}
	if req.RequestURI != rawRequestURI {
		t.Fatalf("ReadRequest changed RequestURI:\n got=%q\nwant=%q", req.RequestURI, rawRequestURI)
	}
	target, err := edgeplane.NetworkExtensionLabTLSTargetURL(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.co.jp", Port: 443})
	if err != nil {
		t.Fatalf("edgeplane.NetworkExtensionLabTLSTargetURL returned error: %v", err)
	}
	// Check the upstream request's URI after re-parsing it through the same path as
	// newSWGHTTPEgressUpstreamRequest.
	upstream, err := http.NewRequest(http.MethodPost, target.String(), nil)
	if err != nil {
		t.Fatalf("rebuild upstream request returned error: %v", err)
	}
	if got := upstream.URL.RequestURI(); got != rawRequestURI {
		t.Fatalf("upstream request-URI was re-encoded across intercept-forward:\n got=%q\nwant=%q", got, rawRequestURI)
	}
}

// HTTP keep-alive on an intercepted connection. Under decrypt-all every resource is intercepted, so a
// Connection: close on each response means a new tunnel per connection; Chrome then runs out of sockets with
// ERR_INSUFFICIENT_RESOURCES, the page's JavaScript never loads, and nothing on it works. This asserts that a
// definitely-framed response is returned WITHOUT Connection: close and that several requests are served on the
// same connection.
func TestNetworkExtensionLabTLSInterceptionKeepAliveServesSequentialRequests(t *testing.T) {
	certNow := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time { return certNow })
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "echo:"+r.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader))
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn := conn.(net.Conn)
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time:       func() time.Time { return certNow },
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	br := bufio.NewReader(client)
	// Two requests in sequence on one TLS connection: if keep-alive is broken the second fails.
	for _, path := range []string{"/first", "/second"} {
		req, err := http.NewRequest(http.MethodGet, "https://accounts.google.com"+path, nil)
		if err != nil {
			t.Fatalf("build request %s: %v", path, err)
		}
		if err := req.Write(client); err != nil {
			t.Fatalf("write request %s: %v", path, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("read response %s (keep-alive likely broken): %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("response %s status = %d, want 200", path, resp.StatusCode)
		}
		if resp.Close {
			t.Fatalf("response %s carried Connection: close — keep-alive not preserved", path)
		}
		want := "echo:https://accounts.google.com" + path
		if string(body) != want {
			t.Fatalf("response %s body = %q, want %q", path, body, want)
		}
	}
}

// With an ALPN of h2, an intercepted connection offers HTTP/2 multiplexing. Many streams on one connection
// means a browser needs one connection per host, so a heavy many-host page under decrypt-all does not spray
// sockets and tunnels, and ERR_INSUFFICIENT_RESOURCES is prevented structurally rather than tuned around.
func TestNetworkExtensionLabTLSInterceptionServesHTTP2Multiplexed(t *testing.T) {
	certNow := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time { return certNow })
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "echo:"+r.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader))
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(conn.(net.Conn), &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		Time:       func() time.Time { return certNow },
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("ALPN negotiated = %q, want h2", got)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(client)
	if err != nil {
		t.Fatalf("NewClientConn returned error: %v", err)
	}
	// Several requests multiplexed concurrently on one h2 connection.
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/stream-%d", i)
			req, _ := http.NewRequest(http.MethodGet, "https://accounts.google.com"+path, nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errs <- fmt.Errorf("stream %d roundtrip: %w", i, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.ProtoMajor != 2 {
				errs <- fmt.Errorf("stream %d proto = HTTP/%d, want 2", i, resp.ProtoMajor)
				return
			}
			want := "echo:https://accounts.google.com" + path
			if string(body) != want {
				errs <- fmt.Errorf("stream %d body = %q, want %q", i, body, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestNetworkExtensionLabTLSWebSocketUpgradeTunnelsBidirectionally(t *testing.T) {
	certNow := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	operatorConfigPath := t.TempDir() + "/operator_config.json"
	if err := os.WriteFile(operatorConfigPath, []byte(`{
  "schema_version": "swg_tenant_restriction_operator_config.v1",
  "status": "active",
  "tenant_id": "tenant_swg_lab",
  "header_values": [
    {
      "ref": "operator_config_ref:google_workspace_allowed_domains",
      "tenant_id": "tenant_swg_lab",
      "saas_application_id": "saas_google_workspace",
      "provider": "google_workspace",
      "header_name": "X-GoogApps-Allowed-Domains",
      "header_value_kind": "configured_allowed_domains",
      "value": "allowed.example",
      "status": "active",
      "metadata": {
        "operator_managed": true,
        "operator_config_value_secret": false,
        "captured_secret_material_committed": false,
        "report_value_material_logged": false
      }
    }
  ],
  "metadata": {
    "designated_operator_config_file": true
  }
}`), 0600); err != nil {
		t.Fatalf("write operator config: %v", err)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true,
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	transport := &webSocketUpgradeRoundTripper{}
	evaluator := decision.Evaluator{
		Policies:      policies,
		PolicyBundle:  bundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-001",
	}
	inspectionEvents := newInspectionEventStore()
	interception.SetHTTPHandler(newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator:        evaluator,
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		ProxyClient:      &http.Client{Transport: transport},
		SWGRuntime:       swgRuntime,
		DecisionStore:    newAccessDecisionStore(),
		InspectionEvents: inspectionEvents,
		LabMode:          true,
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	defer client.Close()
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	request := strings.Join([]string{
		"GET /ws HTTP/1.1",
		"Host: accounts.google.com",
		"Connection: keep-alive, Upgrade",
		"Upgrade: websocket",
		"Sec-WebSocket-Key: opaque-key",
		"Sec-WebSocket-Version: 13",
		"",
		"",
	}, "\r\n")
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("client websocket handshake write returned error: %v", err)
	}
	reader := bufio.NewReader(client)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read TLS websocket response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!headerTokenContains(resp.Header, "Connection", "upgrade") ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("websocket response status/headers = %d %#v, want 101 upgrade", resp.StatusCode, resp.Header)
	}
	if transport.request == nil {
		t.Fatal("upstream websocket request was not observed")
	}
	if got := transport.request.URL.String(); got != "https://accounts.google.com/ws" {
		t.Fatalf("upstream websocket URL = %q, want decrypted HTTPS target URL", got)
	}
	if got := transport.request.Header.Get("Connection"); got != "Upgrade" {
		t.Fatalf("upstream websocket Connection = %q, want Upgrade", got)
	}
	if got := transport.request.Header.Get("Upgrade"); got != "websocket" {
		t.Fatalf("upstream websocket Upgrade = %q, want websocket", got)
	}
	if got := transport.request.Header.Get("Sec-WebSocket-Key"); got != "opaque-key" {
		t.Fatalf("upstream websocket key = %q, want preserved", got)
	}
	if got := transport.request.Header.Get("X-GoogApps-Allowed-Domains"); got != "allowed.example" {
		t.Fatalf("Google tenant restriction header = %q, want configured value", got)
	}
	if got := transport.request.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader); got != "" {
		t.Fatalf("SWG target control header leaked upstream: %q", got)
	}
	if transport.peer == nil {
		t.Fatal("upstream websocket peer was not created")
	}
	defer transport.peer.Close()
	// The tunnel relays through unbuffered conns, so a frame Write blocks until the relay both reads it
	// AND forwards it to the other side — and that forward blocks until this test reads the far end. Doing
	// Write-then-Read serially is therefore a head-of-line deadlock that only "passes" when TLS-record
	// buffering happens to let the Write return early; on a slow/loaded CI runner it spuriously hits
	// "write pipe: i/o timeout". Run each frame's Write concurrently with the matching far-end Read, and
	// give the deadline generous headroom now that neither side blocks the other.
	if err := transport.peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set upstream peer deadline: %v", err)
	}
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("refresh client deadline: %v", err)
	}

	clientFrame := []byte("client-websocket-frame")
	writeErr := make(chan error, 1)
	go func() { _, err := client.Write(clientFrame); writeErr <- err }()
	upstreamGot := make([]byte, len(clientFrame))
	if _, err := io.ReadFull(transport.peer, upstreamGot); err != nil {
		t.Fatalf("read upstream websocket frame: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client websocket frame write returned error: %v", err)
	}
	if string(upstreamGot) != string(clientFrame) {
		t.Fatalf("upstream websocket frame = %q, want %q", upstreamGot, clientFrame)
	}

	serverFrame := []byte("server-websocket-frame")
	go func() { _, err := transport.peer.Write(serverFrame); writeErr <- err }()
	downstreamGot := make([]byte, len(serverFrame))
	if _, err := io.ReadFull(reader, downstreamGot); err != nil {
		t.Fatalf("read downstream websocket frame: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("server websocket frame write returned error: %v", err)
	}
	if string(downstreamGot) != string(serverFrame) {
		t.Fatalf("downstream websocket frame = %q, want %q", downstreamGot, serverFrame)
	}

	events := inspectionEvents.ListByTenant("tenant_swg_lab")
	if len(events) != 1 {
		t.Fatalf("inspection event count = %d, want 1", len(events))
	}
	if !swg.MetadataBool(events[0].Metadata, "runtime_header_injection_observed") ||
		!swg.MetadataBool(events[0].Metadata, "network_extension_runtime_used") {
		t.Fatalf("inspection metadata missing runtime flags: %#v", events[0].Metadata)
	}
}

func TestSWGHTTPEgressReturnsUpstreamRedirectWithoutFollowing(t *testing.T) {
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	operatorConfigPath := t.TempDir() + "/operator_config.json"
	if err := os.WriteFile(operatorConfigPath, []byte(`{
  "schema_version": "swg_tenant_restriction_operator_config.v1",
  "status": "active",
  "tenant_id": "tenant_swg_lab",
  "header_values": [
    {
      "ref": "operator_config_ref:google_workspace_allowed_domains",
      "tenant_id": "tenant_swg_lab",
      "saas_application_id": "saas_google_workspace",
      "provider": "google_workspace",
      "header_name": "X-GoogApps-Allowed-Domains",
      "header_value_kind": "configured_allowed_domains",
      "value": "allowed.example",
      "status": "active",
      "metadata": {
        "operator_managed": true,
        "operator_config_value_secret": false,
        "captured_secret_material_committed": false,
        "report_value_material_logged": false
      }
    }
  ],
  "metadata": {
    "designated_operator_config_file": true
  }
}`), 0600); err != nil {
		t.Fatalf("write operator config: %v", err)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true,
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	redirectBody := &readTrackingReadCloser{}
	transport := &redirectRecordingHTTPRoundTripper{redirectBody: redirectBody}
	handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{
			Policies:      policies,
			PolicyBundle:  bundle,
			EdgeRegionID:  "local",
			EdgeClusterID: "local-edge-001",
		},
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		ProxyClient:      &http.Client{Transport: transport},
		SWGRuntime:       swgRuntime,
		DecisionStore:    newAccessDecisionStore(),
		InspectionEvents: newInspectionEventStore(),
		LabMode:          true,
	})

	req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "https://accounts.google.com/signin/v2/identifier" {
		t.Fatalf("Location = %q, want upstream redirect location", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "0" {
		t.Fatalf("Content-Length = %q, want 0 for body-suppressed redirect", got)
	}
	if redirectBody.readCalled {
		t.Fatal("redirect response body was read; redirect should return headers without waiting for upstream body")
	}
	if len(transport.requests) != 1 {
		t.Fatalf("upstream request count = %d, want one non-followed redirect request", len(transport.requests))
	}
	if got := transport.requests[0].Header.Get("X-GoogApps-Allowed-Domains"); got != "allowed.example" {
		t.Fatalf("Google tenant restriction header = %q, want configured value", got)
	}
}

func TestNetworkExtensionLabTLSForwardStatusClassification(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		outcome string
		want    string
	}{
		{
			name:    "upstream redirect",
			status:  http.StatusFound,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamResponse,
			want:    "upstream_redirect",
		},
		{
			name:    "policy denied",
			status:  http.StatusForbidden,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomePolicyDenied,
			want:    "policy_denied",
		},
		{
			name:    "upstream client error",
			status:  http.StatusForbidden,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamResponse,
			want:    "upstream_client_error",
		},
		{
			name:    "upstream request failed",
			status:  http.StatusBadGateway,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed,
			want:    "egress_upstream_request_failed",
		},
		{
			name:    "upstream server error",
			status:  http.StatusBadGateway,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamResponse,
			want:    "upstream_server_error",
		},
		{
			name:    "rewrite failed",
			status:  http.StatusBadGateway,
			outcome: edgeplane.EdgeSWGHTTPEgressOutcomeRewriteFailed,
			want:    "egress_rewrite_failed",
		},
		{
			name:    "unclassified edge server error",
			status:  http.StatusBadGateway,
			outcome: "",
			want:    "edge_server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := edgeplane.NewNetworkExtensionLabTLSResponseRecorder()
			recorder.WriteHeader(tt.status)
			recorder.SetSWGHTTPEgressOutcome(tt.outcome)
			outcome := edgeplane.NetworkExtensionLabTLSForwardOutcomeCategory(recorder)
			if tt.outcome == "" && outcome != "unclassified" {
				t.Fatalf("outcome category = %q, want unclassified", outcome)
			}
			if got := edgeplane.NetworkExtensionLabTLSForwardStatusCategory(recorder.StatusCode(), outcome); got != tt.want {
				t.Fatalf("status category = %q, want %q", got, tt.want)
			}
		})
	}
}

// Reproduces the original failure. A Google sign-in depends on Cookie, Origin and Referer for its CSRF and
// session checks. If interception and forwarding drop them, Google answers 401 or 400 and the form's "next"
// does nothing. This asserts the auth-critical headers reach the upstream faithfully and that only hop-by-hop
// headers are removed.
func TestNetworkExtensionLabTLSForwardPreservesAuthCriticalHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://accounts.google.co.jp/v3/signin/_/AccountsSignInUi/data/batchexecute", strings.NewReader("f.req=%5B%5B%5B"))
	req.Header.Set("Cookie", "__Host-GAPS=1:abcDEF_-0123456789:zzz; ACCOUNT_CHOOSER=ag-XYZ; SMSV=ADHTe-1234")
	req.Header.Set("Origin", "https://accounts.google.co.jp")
	req.Header.Set("Referer", "https://accounts.google.co.jp/v3/signin/identifier?flowName=GlifWebSignIn")
	req.Header.Set("X-Same-Domain", "1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	// Hop-by-hop headers must not reach the upstream.
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Proxy-Connection", "keep-alive")

	forwarded := swgEgressForwardHeadersForRequest(req)

	for _, name := range []string{"Cookie", "Origin", "Referer", "X-Same-Domain", "Content-Type"} {
		if forwarded.Get(name) != req.Header.Get(name) {
			t.Fatalf("auth-critical header %q not preserved: got=%q want=%q", name, forwarded.Get(name), req.Header.Get(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection"} {
		if forwarded.Get(name) != "" {
			t.Fatalf("hop-by-hop header %q leaked upstream: %q", name, forwarded.Get(name))
		}
	}
}

func TestNetworkExtensionLabTLSForwardUpstreamErrorCategory(t *testing.T) {
	recorder := edgeplane.NewNetworkExtensionLabTLSResponseRecorder()
	recorder.SetSWGHTTPEgressOutcome(edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed)
	recorder.SetSWGHTTPEgressUpstreamErrorCategory(edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError)
	outcome := edgeplane.NetworkExtensionLabTLSForwardOutcomeCategory(recorder)

	if got := edgeplane.NetworkExtensionLabTLSForwardUpstreamErrorCategory(recorder, outcome); got != edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError {
		t.Fatalf("upstream error category = %q, want %q", got, edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError)
	}

	recorder.SetSWGHTTPEgressOutcome(edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamResponse)
	outcome = edgeplane.NetworkExtensionLabTLSForwardOutcomeCategory(recorder)
	if got := edgeplane.NetworkExtensionLabTLSForwardUpstreamErrorCategory(recorder, outcome); got != edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNone {
		t.Fatalf("upstream response category = %q, want %q", got, edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNone)
	}
}

func TestNetworkExtensionLabTLSForwardWriteFailureLogsAbortedNotCompleted(t *testing.T) {
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionForwardOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if writer, ok := w.(swgHTTPEgressOutcomeWriter); ok {
			writer.SetSWGHTTPEgressOutcome(edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed)
		}
		if writer, ok := w.(swgHTTPEgressUpstreamErrorCategoryWriter); ok {
			writer.SetSWGHTTPEgressUpstreamErrorCategory(edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection)
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"redacted"}`))
	}))
	req := httptest.NewRequest(http.MethodPost, "https://accounts.google.com/background", strings.NewReader("payload"))
	req.ContentLength = int64(len("payload"))

	var logs bytes.Buffer
	originalOutput := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer log.SetOutput(originalOutput)
	defer log.SetFlags(originalFlags)

	err := interception.ServeForwardedHTTP(failingNetworkExtensionLabTLSWriter{err: net.ErrClosed}, req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 443,
	})
	if err == nil {
		t.Fatal("serveForwardedHTTP returned nil, want write failure")
	}
	got := logs.String()
	for _, want := range []string{
		"progress=http_forward_aborted",
		"status_code=502",
		"egress_outcome_category=upstream_request_failed",
		"upstream_error_category=closed_connection",
		"downstream_write_category=closed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("logs missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "progress=http_forward_completed") {
		t.Fatalf("logs contained completed forward despite write failure:\n%s", got)
	}
}

func TestNetworkExtensionLabTLSForwardStreamsFlushedResponseIncrementally(t *testing.T) {
	// The handler writes "first", flushes, waits for release, and only then writes "second". Receiving "first"
	// while the handler is still waiting means "second" has not been written yet — which proves the response
	// is being delivered as it goes rather than buffered whole.
	release := make(chan struct{})
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionForwardOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("first")); err != nil {
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("recorder does not implement http.Flusher")
			return
		}
		flusher.Flush()
		<-release
		_, _ = w.Write([]byte("second"))
	}))
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodGet, "https://accounts.google.com/stream", nil)
	done := make(chan error, 1)
	go func() {
		err := interception.ServeForwardedHTTP(pw, req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443})
		_ = pw.Close()
		done <- err
	}()

	resp, err := http.ReadResponse(bufio.NewReader(pr), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("streamed response Content-Length = %q, want none (chunked framing)", got)
	}
	// A streaming response is framed chunked, so keep-alive is possible and no Connection: close is added.
	if resp.Close {
		t.Fatalf("resp.Close = true, want keep-alive (chunked) framing")
	}
	if len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("Transfer-Encoding = %v, want [chunked]", resp.TransferEncoding)
	}
	firstChunk := make([]byte, len("first"))
	if _, err := io.ReadFull(resp.Body, firstChunk); err != nil {
		t.Fatalf("read first chunk before releasing handler: %v", err)
	}
	if string(firstChunk) != "first" {
		t.Fatalf("first chunk = %q, want first", firstChunk)
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read remaining streamed body: %v", err)
	}
	if string(rest) != "second" {
		t.Fatalf("remaining body = %q, want second", rest)
	}
	if err := <-done; err != nil {
		t.Fatalf("serveForwardedHTTP returned error: %v", err)
	}
}

func TestNetworkExtensionLabTLSForwardStreamsLargeResponseWithoutContentLength(t *testing.T) {
	// A body past the threshold is written through rather than buffered to a definite length, which is what
	// stops memory growing and the flow stalling. There is no Content-Length; it is framed chunked, so
	// keep-alive still works.
	payload := bytes.Repeat([]byte("x"), edgeplane.NetworkExtensionLabTLSResponseStreamThreshold+8192)
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionForwardOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	var out bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "https://accounts.google.com/large", nil)
	if err := interception.ServeForwardedHTTP(&out, req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443}); err != nil {
		t.Fatalf("serveForwardedHTTP returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(out.Bytes())), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("large streamed response Content-Length = %q, want none", got)
	}
	// A large response is chunked too, so keep-alive holds and the connection is reused rather than the
	// sockets running out on a heavy page.
	if resp.Close {
		t.Fatalf("resp.Close = true, want keep-alive (chunked) framing")
	}
	if len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("Transfer-Encoding = %v, want [chunked]", resp.TransferEncoding)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != len(payload) {
		t.Fatalf("streamed body length = %d, want %d", len(body), len(payload))
	}
}

func TestNetworkExtensionLabTLSForwardStreamsServerSentEventsImmediately(t *testing.T) {
	// SSE streams immediately however small it is. This checks there is no Content-Length and that events
	// flow in real time rather than being held until the threshold is reached.
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionForwardOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hello\n\n"))
	}))
	var out bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "https://accounts.google.com/events", nil)
	if err := interception.ServeForwardedHTTP(&out, req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443}); err != nil {
		t.Fatalf("serveForwardedHTTP returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(out.Bytes())), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("SSE response Content-Length = %q, want none", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "data: hello\n\n" {
		t.Fatalf("SSE body = %q, want event payload", body)
	}
}

func TestNetworkExtensionLabTLSForwardBuffersSmallResponseWithContentLength(t *testing.T) {
	// A small response that fits under the threshold is returned in one piece with a Content-Length. This
	// checks the existing framing behaviour has not regressed.
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionForwardOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("small"))
	}))
	var out bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "https://accounts.google.com/small", nil)
	if err := interception.ServeForwardedHTTP(&out, req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443}); err != nil {
		t.Fatalf("serveForwardedHTTP returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(out.Bytes())), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := resp.Header.Get("Content-Length"); got != "5" {
		t.Fatalf("small response Content-Length = %q, want 5", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "small" {
		t.Fatalf("small response body = %q, want small", body)
	}
}

func TestNetworkExtensionLabTLSInterceptionBypassHostsRawForwardUnderDecryptAll(t *testing.T) {
	// Even under decrypt-all (`*`), a bypass host is raw-forwarded rather than intercepted. The Edge decides
	// what to bypass from the SNI or the host.
	interception := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	interception.SetBypassHosts([]string{"anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai"})

	cases := []struct {
		host          string
		wantIntercept bool // true means intercept and decrypt; false means raw-forward
	}{
		{"example.com", true},
		{"accounts.google.com", true},
		{"anthropic.com", false},
		{"api.anthropic.com", false},
		{"statsig.anthropic.com", false},
		{"claude.ai", false},
		{"foo.claude.ai", false},
		{"notanthropic.com", true},
	}
	for _, tc := range cases {
		got := interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: tc.host, Port: 443})
		if got != tc.wantIntercept {
			t.Errorf("Matches(%q) = %v, want %v (true=intercept, false=bypass/raw_forward)", tc.host, got, tc.wantIntercept)
		}
	}

	// With no bypass configured, decrypt-all still intercepts everything: no regression.
	plain := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	if !plain.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "anthropic.com", Port: 443}) {
		t.Fatal("without bypass hosts, decrypt-all must intercept anthropic.com")
	}
}

func TestNetworkExtensionLabTLSSNIBasedMatchesByRouteSNI(t *testing.T) {
	// Deciding from the SNI: even when route.Host is an address — Chrome's connect-by-IP — intercept or
	// raw_forward is decided from route.SNI, which the tunnel handler peeked from the ClientHello.
	certNow := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time { return certNow })
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)

	// On an IP flow, an SNI of accounts.google.com is still intercepted.
	if !interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "2606:4700::1", Port: 443, SNI: "accounts.google.com"}) {
		t.Error("SNI=accounts.google.com over IPv6 route must intercept")
	}
	// An SNI of example.com is raw-forwarded, not intercepted.
	if interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "2606:4700::1", Port: 443, SNI: "example.com"}) {
		t.Error("SNI=example.com must NOT intercept (raw_forward)")
	}
	// With no SNI it falls back to route.Host.
	if !interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443}) {
		t.Error("no SNI: fallback to route.Host must intercept accounts.google.com")
	}
	if interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "93.184.216.34", Port: 443}) {
		t.Error("no SNI + public IP host must NOT intercept")
	}
	// A bypass host is raw-forwarded in SNI mode too: the match is made against the SNI as well.
	interception.SetBypassHosts([]string{"anthropic.com", "*.anthropic.com"})
	if interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "2606:4700::1", Port: 443, SNI: "api.anthropic.com"}) {
		t.Error("SNI=api.anthropic.com must be bypassed (raw_forward), not intercepted")
	}
}

func TestNetworkExtensionLabTLSRecordedRedirectResponsePreservesUpstreamHeaders(t *testing.T) {
	recorder := edgeplane.NewNetworkExtensionLabTLSResponseRecorder()
	recorder.Header().Set("Location", "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Faccounts.google.com%2F")
	recorder.Header().Set("Content-Security-Policy", "script-src nonce")
	recorder.Header().Add("Set-Cookie", "session=opaque; Secure; HttpOnly")
	recorder.WriteHeader(http.StatusFound)

	var out bytes.Buffer
	if err := edgeplane.WriteNetworkExtensionLabTLSRecordedResponse(&out, recorder); err != nil {
		t.Fatalf("edgeplane.WriteNetworkExtensionLabTLSRecordedResponse returned error: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"HTTP/1.1 302 Found\r\n",
		"Content-Length: 0\r\n",
		"Content-Security-Policy: script-src nonce\r\n",
		"Location: https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Faccounts.google.com%2F\r\n",
		"Set-Cookie: session=opaque; Secure; HttpOnly\r\n",
		"\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("redirect response missing %q in:\n%s", want, got)
		}
	}
	// A definitely-framed response is keep-alive now, so no Connection: close is added. With it, Chrome cannot
	// reuse the connection and runs out of sockets under decrypt-all.
	if strings.Contains(got, "Connection: close") {
		t.Fatalf("buffered redirect response must NOT force Connection: close (keep-alive required):\n%s", got)
	}
}

func TestNetworkExtensionLabTLSInterceptionProbeReturnsSyntheticResponseWithoutForwarding(t *testing.T) {
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	for _, requestTarget := range []string{
		"/?dsse_lab_tls_probe=1",
		"/?dsse_lab_tls_probe",
		"/?dsse_probe=1",
		"/dsse-lab-tls-probe",
		"/dsse-lab-tls-probe?nonce=path-query",
		"/signin/v2/identifier?continue=https%3A%2F%2Faccounts.google.com%2Fdsse-lab-tls-probe%3Fnonce%3Dencoded-continue",
		"https://accounts.google.com/dsse-lab-tls-probe?nonce=absolute-form",
	} {
		t.Run(requestTarget, func(t *testing.T) {
			interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"accounts.google.com"}, func() time.Time {
				return certNow
			})
			if err != nil {
				t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
			}
			forwarded := make(chan struct{}, 1)
			interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded <- struct{}{}
				w.WriteHeader(http.StatusTeapot)
			}))

			conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
				Host: "accounts.google.com",
				Port: 443,
			})
			if err != nil {
				t.Fatalf("OpenTCPConnection returned error: %v", err)
			}
			defer conn.Close()
			netConn, ok := conn.(net.Conn)
			if !ok {
				t.Fatalf("conn type %T does not implement net.Conn", conn)
			}
			roots := x509.NewCertPool()
			roots.AddCert(interception.RootCertificate())
			client := tls.Client(netConn, &tls.Config{
				ServerName: "accounts.google.com",
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
				Time: func() time.Time {
					return certNow
				},
			})
			if err := client.Handshake(); err != nil {
				t.Fatalf("TLS handshake returned error: %v", err)
			}
			if _, err := client.Write([]byte("GET " + requestTarget + " HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatalf("client write returned error: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read TLS HTTP response: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "dsse lab tls interception probe ok\n" {
				t.Fatalf("response status/body = %d/%q, want synthetic probe 200", resp.StatusCode, body)
			}
			if got := resp.Header.Get("X-Dsse-Lab-TLS-Interception"); got != "observed" {
				t.Fatalf("probe response interception header = %q, want observed", got)
			}
			select {
			case <-forwarded:
				t.Fatal("probe request was forwarded to SWG handler")
			default:
			}
		})
	}
}

func TestNetworkExtensionLabTLSInterceptionProbeOnlyShortCircuitsNonProbeWithoutForwarding(t *testing.T) {
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	interception.SetProbeOnly(true)
	forwarded := make(chan struct{}, 1)
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- struct{}{}
		w.WriteHeader(http.StatusTeapot)
	}))

	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("client SetDeadline returned error: %v", err)
	}
	if _, err := client.Write([]byte("POST /not-the-probe HTTP/1.1\r\nHost: accounts.google.com\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\npartial-body")); err != nil {
		t.Fatalf("client write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("response status/body = %d/%q, want synthetic non-probe 204", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Dsse-Lab-TLS-Interception"); got != "probe-only" {
		t.Fatalf("non-probe response interception header = %q, want probe-only", got)
	}
	select {
	case <-forwarded:
		t.Fatal("non-probe request was forwarded to SWG handler in probe-only mode")
	default:
	}
}

func TestSWGHTTPEgressUpstreamRequestPreservesInboundBodyLength(t *testing.T) {
	body := "continue=https%3A%2F%2Faccounts.google.com%2F&identifier=user"
	req := httptest.NewRequest(http.MethodPost, edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/signin/v2/challenge")
	target, err := swgHTTPEgressTargetURLFromRequest(req)
	if err != nil {
		t.Fatalf("swgHTTPEgressTargetURLFromRequest returned error: %v", err)
	}

	upstream, err := newSWGHTTPEgressUpstreamRequest(req, target)
	if err != nil {
		t.Fatalf("newSWGHTTPEgressUpstreamRequest returned error: %v", err)
	}
	if upstream.ContentLength != int64(len(body)) {
		t.Fatalf("upstream ContentLength = %d, want %d", upstream.ContentLength, len(body))
	}
	if len(upstream.TransferEncoding) != 0 {
		t.Fatalf("upstream TransferEncoding = %#v, want none for known-length body", upstream.TransferEncoding)
	}
	if got := upstream.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("upstream Content-Type = %q, want forwarded form content type", got)
	}
	if got := upstream.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader); got != "" {
		t.Fatalf("SWG target control header leaked upstream: %q", got)
	}
}

func TestNetworkExtensionLabTLSInterceptionConnectionOutlivesRequestContext(t *testing.T) {
	certNow := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"example.com"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := interception.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "example.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	cancel()

	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "example.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake after request context cancel returned error: %v", err)
	}
}

func testNetworkExtensionLabTLSSWGPolicyBundle() (model.PolicyBundle, []model.Policy) {
	profileID := "ip_swg_default_tls_decrypt"
	bundle := model.PolicyBundle{
		ID:       "pb_swg_preflight_m1583",
		TenantID: "tenant_swg_lab",
		Version:  "swg-saas-tenant-preflight",
		Status:   "active",
		SaaSCatalog: []model.SaaSCatalogEntry{
			{
				TenantID:          "tenant_swg_lab",
				SaaSApplicationID: "saas_google_workspace",
				Name:              "Google Workspace",
				Provider:          "google_workspace",
				Category:          "productivity",
				DomainPatterns:    []string{"accounts.google.com"},
				SNIPatterns:       []string{"accounts.google.com"},
			},
		},
		SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{
			{
				ID:                "swg_tr_google_workspace_lab",
				TenantID:          "tenant_swg_lab",
				SaaSApplicationID: "saas_google_workspace",
				Provider:          "google_workspace",
				HeaderName:        "X-GoogApps-Allowed-Domains",
				HeaderValueRef:    "operator_config_ref:google_workspace_allowed_domains",
				HeaderValueKind:   "configured_allowed_domains",
				EnforcementMode:   "inject_on_default_tls_decrypt",
				Status:            "active",
			},
		},
		InspectionProfiles: []model.InspectionProfile{
			{
				ID:                         profileID,
				TenantID:                   "tenant_swg_lab",
				Name:                       "Default TLS decrypt",
				InspectionMode:             "default_tls_decrypt",
				TLSInterceptionEnabled:     true,
				NetworkExtensionDependency: "mac_swg_steering_required",
				Status:                     "active",
			},
		},
	}
	policies := []model.Policy{
		{
			ID:       "pol_google_workspace_swg_allow_001",
			TenantID: "tenant_swg_lab",
			Name:     "Google Workspace tenant header preflight",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":          "human",
				"saas_application_id": "saas_google_workspace",
				"service_family":      "https",
				"destination_port":    float64(443),
				"steering_mode":       "network_extension",
			},
			Action:              model.PolicyAction{Decision: "allow"},
			InspectionProfileID: &profileID,
			Status:              "active",
		},
	}
	return bundle, policies
}

func TestNetworkExtensionTLSInterceptionDialerFallsBackForUnmatchedHost(t *testing.T) {
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"example.com"}, time.Now)
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	conn := newRecordingNetworkExtensionRuntimeCopyTCPConnection([]byte("raw-downstream"))
	base := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	dialer := edgeplane.NetworkExtensionRuntimeCopyTLSInterceptionDialer{
		Base:        base,
		Intercepter: interception,
	}
	gotConn, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "not-intercepted.example",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	if gotConn != conn {
		t.Fatalf("conn = %T, want base dialer connection", gotConn)
	}
	if len(base.routes) != 1 || base.routes[0].Host != "not-intercepted.example" {
		t.Fatalf("base routes = %+v, want unmatched host routed to base", base.routes)
	}
}

func TestNetworkExtensionLabTLSInterceptionCatchAllMatchesAny443Route(t *testing.T) {
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	if interception == nil {
		t.Fatal("interception = nil, want catch-all lab TLS interception")
	}
	if !interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 443}) {
		t.Fatal("catch-all did not match domain:443 route")
	}
	if !interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "192.0.2.10", Port: 443}) {
		t.Fatal("catch-all did not match IPv4:443 route")
	}
	if interception.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "accounts.google.com", Port: 8443}) {
		t.Fatal("catch-all matched non-443 route")
	}
}

func TestNetworkExtensionLabTLSInterceptionCatchAllUsesSNILeafForIPRoute(t *testing.T) {
	certNow := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	conn, err := interception.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "192.0.2.10",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection returned error: %v", err)
	}
	defer conn.Close()
	netConn, ok := conn.(net.Conn)
	if !ok {
		t.Fatalf("conn type %T does not implement net.Conn", conn)
	}
	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(netConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("peer certificates empty")
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.CommonName != "accounts.google.com" {
		t.Fatalf("leaf CommonName = %q, want accounts.google.com", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "accounts.google.com" {
		t.Fatalf("leaf DNSNames = %#v, want accounts.google.com", leaf.DNSNames)
	}
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("client write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Dsse-Lab-TLS-Target-Host"); got != "accounts.google.com" {
		t.Fatalf("target host header = %q, want HTTP Host domain", got)
	}
}

func TestNetworkExtensionLabTLSTargetURLPrefersHTTPHostForIPRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dsse-lab-tls-probe?nonce=ip-route", nil)
	req.Host = "accounts.google.com"
	target, err := edgeplane.NetworkExtensionLabTLSTargetURL(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "192.0.2.10",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("edgeplane.NetworkExtensionLabTLSTargetURL returned error: %v", err)
	}
	if got, want := target.String(), "https://accounts.google.com/dsse-lab-tls-probe?nonce=ip-route"; got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func TestNetworkExtensionLabTLSTargetURLPrefersAbsoluteFormHostForIPRoute(t *testing.T) {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        mustParseURLForNetworkExtensionTest(t, "https://accounts.google.com/dsse-lab-tls-probe?nonce=absolute-ip-route"),
		RequestURI: "https://accounts.google.com/dsse-lab-tls-probe?nonce=absolute-ip-route",
	}
	target, err := edgeplane.NetworkExtensionLabTLSTargetURL(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "192.0.2.10",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("edgeplane.NetworkExtensionLabTLSTargetURL returned error: %v", err)
	}
	if got, want := target.String(), "https://accounts.google.com/dsse-lab-tls-probe?nonce=absolute-ip-route"; got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func TestNetworkExtensionLabTLSTargetURLFormatsIPv6RouteHost(t *testing.T) {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: "/dsse-lab-tls-probe", RawQuery: "nonce=ipv6-route"},
		RequestURI: "/dsse-lab-tls-probe?nonce=ipv6-route",
	}
	target, err := edgeplane.NetworkExtensionLabTLSTargetURL(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "[2001:db8::44]",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("edgeplane.NetworkExtensionLabTLSTargetURL returned error: %v", err)
	}
	if got, want := target.String(), "https://[2001:db8::44]/dsse-lab-tls-probe?nonce=ipv6-route"; got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func TestNetworkExtensionLabTLSTargetURLKeepsRouteDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	req.Host = "spoofed.example"
	target, err := edgeplane.NetworkExtensionLabTLSTargetURL(req, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "accounts.google.com",
		Port: 443,
	})
	if err != nil {
		t.Fatalf("edgeplane.NetworkExtensionLabTLSTargetURL returned error: %v", err)
	}
	if got, want := target.String(), "https://accounts.google.com/path"; got != want {
		t.Fatalf("target URL = %q, want %q", got, want)
	}
}

func mustParseURLForNetworkExtensionTest(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return parsed
}

func TestNetworkExtensionLabTLSRouteDiagnosticCategoriesAreNonSecret(t *testing.T) {
	if got := edgeplane.NetworkExtensionLabTLSRouteHostCategory("accounts.google.com"); got != "domain" {
		t.Fatalf("domain route host category = %q, want domain", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSRouteHostCategory("192.0.2.10"); got != "ipv4" {
		t.Fatalf("IPv4 route host category = %q, want ipv4", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSRouteHostCategory("2001:db8::1"); got != "ipv6" {
		t.Fatalf("IPv6 route host category = %q, want ipv6", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSRouteHostCategory("bad host value"); got != "invalid" {
		t.Fatalf("invalid route host category = %q, want invalid", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSRoutePortCategory(443); got != "port_443" {
		t.Fatalf("port category = %q, want port_443", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSRoutePortCategory(8443); got != "other_port" {
		t.Fatalf("port category = %q, want other_port", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSALPNCategory("http/1.1"); got != "http_1_1" {
		t.Fatalf("ALPN category = %q, want http_1_1", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSALPNCategory("h2"); got != "h2" {
		t.Fatalf("ALPN category = %q, want h2", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("accounts.google.com", "accounts.google.com"); got != "exact" {
		t.Fatalf("SNI match category = %q, want exact", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("www.google.com", "accounts.google.com"); got != "mismatch" {
		t.Fatalf("SNI match category = %q, want mismatch", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("accounts.google.com", "172.217.221.84"); got != "route_ip_sni_domain" {
		t.Fatalf("SNI match category = %q, want route_ip_sni_domain", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("172.217.221.84", "accounts.google.com"); got != "route_domain_sni_ip" {
		t.Fatalf("SNI match category = %q, want route_domain_sni_ip", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("192.0.2.1", "192.0.2.2"); got != "ip_mismatch" {
		t.Fatalf("SNI match category = %q, want ip_mismatch", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSSNIMatchCategory("", "accounts.google.com"); got != "empty" {
		t.Fatalf("SNI match category = %q, want empty", got)
	}
}

func TestNetworkExtensionLabTLSRequestDiagnosticCategoriesAreNonSecret(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dsse-lab-tls-probe?nonce=test", nil)
	req.Host = "accounts.google.com"
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if got := edgeplane.NetworkExtensionLabTLSRequestMethodCategory(req); got != "GET" {
		t.Fatalf("method category = %q, want GET", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSFetchDestCategory(req); got != "document" {
		t.Fatalf("fetch dest category = %q, want document", got)
	}
	if got := edgeplane.NetworkExtensionLabTLSAcceptCategory(req); got != "document" {
		t.Fatalf("accept category = %q, want document", got)
	}
	// The length comes from the path rather than a literal: what this asserts is the SHAPE (a length and a
	// digest, never the path itself), and pinning the number meant renaming the probe route broke a test
	// about secrecy.
	wantPrefix := fmt.Sprintf("len_%d_sha256_", len(req.URL.Path))
	if got := edgeplane.NetworkExtensionLabTLSFingerprint(req.URL.Path); !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("path fingerprint = %q, want length-prefixed sha256 (%s…)", got, wantPrefix)
	}
}

func TestNetworkExtensionRuntimeCopySessionAllowsEmptyDownstreamForMarkedConnection(t *testing.T) {
	conn := &optionalEmptyNetworkExtensionRuntimeCopyConnection{}
	dialer := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID:       "tenant_lab_001",
		Dialer:         dialer,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})

	payload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           "req-empty-downstream-001",
		"operation":            edgeplane.NetworkExtensionRuntimeCopySessionOperationOpen,
		"application_id":       "app_dummy_postgres",
		"destination_host":     "example.com",
		"destination_port":     443,
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("client-finished-flight")),
	})

	if payload["status"] != "ok" || payload["category"] != "session_exchange_completed" {
		t.Fatalf("payload status/category = %v/%v, want ok/session_exchange_completed; payload=%+v", payload["status"], payload["category"], payload)
	}
	if _, ok := payload["downstream_payload_b64"]; ok {
		t.Fatalf("downstream_payload_b64 present for empty downstream response: %+v", payload)
	}
	if len(conn.writes) != 1 || string(conn.writes[0]) != "client-finished-flight" {
		t.Fatalf("writes = %q, want client-finished-flight", conn.writes)
	}
}

func TestNetworkExtensionRuntimeCopySessionReturnsEmptyFirstDownstreamNearDrainWait(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := delayedEmptyDownstreamNetConn{Conn: client}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	startedAt := time.Now()
	downstream, sessionClosed, err := edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream(ctx, conn)
	if err != nil {
		t.Fatalf("edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream returned error: %v", err)
	}
	if sessionClosed {
		t.Fatal("sessionClosed = true, want false")
	}
	if len(downstream) != 0 {
		t.Fatalf("downstream = %q, want empty downstream", downstream)
	}
	if elapsed := time.Since(startedAt); elapsed > edgeplane.NetworkExtensionRuntimeCopySessionEmptyDownstreamWait+750*time.Millisecond {
		t.Fatalf("empty first exchange took %s, want near empty-downstream wait", elapsed)
	}
}

func TestNetworkExtensionRuntimeCopySessionAllowsEmptyLaterExchangeBeforeContextDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := delayedEmptyDownstreamNetConn{Conn: client}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	startedAt := time.Now()
	downstream, sessionClosed, err := edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream(ctx, conn)
	if err != nil {
		t.Fatalf("edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream returned error: %v", err)
	}
	if sessionClosed {
		t.Fatal("sessionClosed = true, want false")
	}
	if len(downstream) != 0 {
		t.Fatalf("downstream = %q, want empty downstream", downstream)
	}
	if elapsed := time.Since(startedAt); elapsed > edgeplane.NetworkExtensionRuntimeCopySessionEmptyDownstreamWait+750*time.Millisecond {
		t.Fatalf("empty later exchange took %s, want near empty-downstream wait", elapsed)
	}
}

func TestNetworkExtensionRuntimeCopySessionMarksClosedWhenDoneSignalFollowsDrainedDownstream(t *testing.T) {
	done := make(chan struct{})
	conn := &doneSignalEmptyDownstreamConn{
		readPayloads: [][]byte{[]byte("tls-http-response-record")},
		done:         done,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	downstream, sessionClosed, err := edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream(ctx, conn)
	if err != nil {
		t.Fatalf("edgeplane.ReadNetworkExtensionRuntimeCopySessionDownstream returned error: %v", err)
	}
	if !sessionClosed {
		t.Fatal("sessionClosed = false, want true after done signal")
	}
	if string(downstream) != "tls-http-response-record" {
		t.Fatalf("downstream = %q, want drained response record", downstream)
	}
}

func TestNetworkExtensionRuntimeCopySessionCarriesLabTLSProbeAcrossSplitClientFlights(t *testing.T) {
	certNow := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("probe request reached SWG forward handler, want synthetic probe response")
	}))
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer: edgeplane.NetworkExtensionRuntimeCopyTLSInterceptionDialer{
			Intercepter: interception,
		},
		Timeout:        2 * time.Second,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})
	sessionConn := newRuntimeCopySessionTLSClientConn(t, handler, "2001:db8::44", 443)
	defer sessionConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(sessionConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if _, err := client.Write([]byte("GET /dsse-lab-tls-probe?nonce=session-split HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("client HTTP write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "dsse lab tls interception probe ok") {
		t.Fatalf("body = %q, want probe ok response", body)
	}
	if !sessionConn.sessionClosedSeen() {
		t.Fatal("sessionClosedSeen = false, want Edge session response to mark closed after probe response")
	}
	if sessionConn.exchangeCount() < 3 {
		t.Fatalf("session exchange count = %d, want split TLS flights plus HTTP request", sessionConn.exchangeCount())
	}
}

func TestNetworkExtensionRuntimeCopySessionWaitsForDelayedLabTLSRedirectResponse(t *testing.T) {
	certNow := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time {
		return certNow
	})
	if err != nil {
		t.Fatalf("edgeplane.NewNetworkExtensionLabTLSInterception returned error: %v", err)
	}
	redirectLocation := "https://accounts.google.com/ServiceLogin"
	interception.SetHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(4 * edgeplane.NetworkExtensionLabTLSDrainWait)
		w.Header().Set("Location", redirectLocation)
		w.WriteHeader(http.StatusFound)
	}))
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "tenant_lab_001",
		Dialer: edgeplane.NetworkExtensionRuntimeCopyTLSInterceptionDialer{
			Intercepter: interception,
		},
		Timeout:        2 * time.Second,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})
	sessionConn := newRuntimeCopySessionTLSClientConn(t, handler, "accounts.google.com", 443)
	defer sessionConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(interception.RootCertificate())
	client := tls.Client(sessionConn, &tls.Config{
		ServerName: "accounts.google.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		Time: func() time.Time {
			return certNow
		},
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake returned error: %v", err)
	}
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: accounts.google.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("client HTTP write returned error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read TLS HTTP response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, http.StatusFound, body)
	}
	if resp.Header.Get("Location") != redirectLocation {
		t.Fatalf("Location = %q, want %q", resp.Header.Get("Location"), redirectLocation)
	}
	if resp.Header.Get("Content-Length") != "0" || len(body) != 0 {
		t.Fatalf("redirect body framing = content-length %q body %q, want Content-Length: 0 with empty body", resp.Header.Get("Content-Length"), body)
	}
}

func TestNetworkExtensionRuntimeCopySessionDrainsAvailableDownstreamForMarkedConnection(t *testing.T) {
	conn := &optionalEmptyNetworkExtensionRuntimeCopyConnection{
		readPayloads: [][]byte{
			[]byte("tls-post-handshake-record"),
			[]byte("tls-http-response-record"),
		},
	}
	dialer := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID:       "tenant_lab_001",
		Dialer:         dialer,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})

	payload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           "req-drain-downstream-001",
		"operation":            edgeplane.NetworkExtensionRuntimeCopySessionOperationOpen,
		"application_id":       "app_dummy_tls",
		"destination_host":     "example.com",
		"destination_port":     443,
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("http-request-flight")),
	})

	downstream, err := decodeBase64String(payload["downstream_payload_b64"])
	if err != nil {
		t.Fatalf("downstream_payload_b64 invalid: %v; payload=%+v", err, payload)
	}
	if string(downstream) != "tls-post-handshake-recordtls-http-response-record" {
		t.Fatalf("downstream = %q, want drained TLS records", downstream)
	}
	if len(conn.writes) != 1 || string(conn.writes[0]) != "http-request-flight" {
		t.Fatalf("writes = %q, want http-request-flight", conn.writes)
	}
}

func TestNetworkExtensionRuntimeCopySessionReturnsDrainedDownstreamOnDestinationClose(t *testing.T) {
	conn := &optionalEmptyNetworkExtensionRuntimeCopyConnection{
		readPayloads: [][]byte{
			[]byte("tls-http-response-record"),
		},
		readErr: io.EOF,
	}
	dialer := &recordingNetworkExtensionRuntimeCopyTCPDialer{conn: conn}
	handler := edgeplane.NewNetworkExtensionRuntimeCopySessionHandler(edgeplane.NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID:       "tenant_lab_001",
		Dialer:         dialer,
		SessionManager: edgeplane.NewNetworkExtensionRuntimeCopySessionManager(time.Minute, 16, time.Now),
	})

	payload := postNetworkExtensionRuntimeCopySessionTestRequest(t, handler, map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           "req-downstream-close-001",
		"operation":            edgeplane.NetworkExtensionRuntimeCopySessionOperationOpen,
		"application_id":       "app_dummy_tls",
		"destination_host":     "example.com",
		"destination_port":     443,
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("http-request-flight")),
	})

	if payload["status"] != "ok" || payload["session_closed"] != true {
		t.Fatalf("payload status/session_closed = %v/%v, want ok/true; payload=%+v", payload["status"], payload["session_closed"], payload)
	}
	downstream, err := decodeBase64String(payload["downstream_payload_b64"])
	if err != nil {
		t.Fatalf("downstream_payload_b64 invalid: %v; payload=%+v", err, payload)
	}
	if string(downstream) != "tls-http-response-record" {
		t.Fatalf("downstream = %q, want tls-http-response-record", downstream)
	}
}

func TestNetworkExtensionRuntimeCopyRoundTripRejectsInvalidSchemaWithTypedError(t *testing.T) {
	handler := newNetworkExtensionRuntimeCopyTestHandler(t)
	body := `{
		"schema_version":"network_extension_runtime_copy_round_trip_request.v0",
		"tenant_id":"tenant_lab_001",
		"request_id":"manual-runtime-copy-check-002",
		"application_id":"default_network_extension_tunnel",
		"upstream_payload_b64":"QQ=="
	}`
	req := httptest.NewRequest(http.MethodPost, edgeplane.NetworkExtensionRuntimeCopyRoundTripPath, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assertNetworkExtensionRuntimeCopyStatus(t, rec, http.StatusBadRequest, "invalid_schema_version")
}

func TestNetworkExtensionRuntimeCopyRoundTripRejectsNonPostWithTypedError(t *testing.T) {
	handler := newNetworkExtensionRuntimeCopyTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, edgeplane.NetworkExtensionRuntimeCopyRoundTripPath, nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assertNetworkExtensionRuntimeCopyStatus(t, rec, http.StatusMethodNotAllowed, "method_not_allowed")
}

func newNetworkExtensionRuntimeCopyTestHandler(t *testing.T) http.Handler {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	return newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
}

func assertNetworkExtensionRuntimeCopyStatus(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCategory string) map[string]any {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("content-type"), "application/json") {
		t.Fatalf("content-type = %q, want application/json", rec.Header().Get("content-type"))
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
	if payload["status"] != "error" || payload["category"] != wantCategory {
		t.Fatalf("payload status/category = %v/%v, want error/%s; payload=%+v", payload["status"], payload["category"], wantCategory, payload)
	}
	return payload
}

func decodeBase64String(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return base64.StdEncoding.DecodeString(text)
}

func postNetworkExtensionRuntimeCopySessionTestRequest(t *testing.T, handler http.Handler, body map[string]any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, edgeplane.NetworkExtensionRuntimeCopySessionPath, bytes.NewReader(payload))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rec.Body.String())
	}
	return decoded
}

type recordingNetworkExtensionRuntimeCopyTCPDialer struct {
	routes []edgeplane.NetworkExtensionRuntimeCopyTCPRoute
	conn   io.ReadWriteCloser
	err    error
}

func (dialer *recordingNetworkExtensionRuntimeCopyTCPDialer) OpenTCPConnection(ctx context.Context, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	dialer.routes = append(dialer.routes, route)
	if dialer.err != nil {
		return nil, dialer.err
	}
	return dialer.conn, nil
}

type recordingHTTPRoundTripper struct {
	request *http.Request
	status  int
	body    string
}

func (transport *recordingHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.request = req.Clone(context.Background())
	transport.request.Header = req.Header.Clone()
	status := transport.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(transport.body)),
		ContentLength: int64(len(transport.body)),
		Request:       req,
	}, nil
}

type redirectRecordingHTTPRoundTripper struct {
	requests     []*http.Request
	redirectBody io.ReadCloser
}

func (transport *redirectRecordingHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(context.Background())
	clone.Header = req.Header.Clone()
	transport.requests = append(transport.requests, clone)
	if len(transport.requests) == 1 {
		body := transport.redirectBody
		if body == nil {
			body = io.NopCloser(strings.NewReader(""))
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Status:     "302 Found",
			Header: http.Header{
				"Location":       []string{"https://accounts.google.com/signin/v2/identifier"},
				"Content-Type":   []string{"text/html; charset=utf-8"},
				"Content-Length": []string{"128"},
			},
			Body:          body,
			ContentLength: 128,
			Request:       req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Status:     "204 No Content",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

type webSocketUpgradeRoundTripper struct {
	request *http.Request
	peer    net.Conn
}

func (transport *webSocketUpgradeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(context.Background())
	clone.Header = req.Header.Clone()
	transport.request = clone
	edgeSide, peer := net.Pipe()
	transport.peer = peer
	return &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Header: http.Header{
			"Connection":           []string{"Upgrade"},
			"Upgrade":              []string{"websocket"},
			"Sec-WebSocket-Accept": []string{"opaque-accept"},
		},
		Body:    edgeSide,
		Request: req,
	}, nil
}

type readTrackingReadCloser struct {
	readCalled bool
}

func (body *readTrackingReadCloser) Read(_ []byte) (int, error) {
	body.readCalled = true
	return 0, io.EOF
}

func (body *readTrackingReadCloser) Close() error {
	return nil
}

type failingNetworkExtensionLabTLSWriter struct {
	err error
}

func (writer failingNetworkExtensionLabTLSWriter) Write(_ []byte) (int, error) {
	return 0, writer.err
}

type recordingNetworkExtensionRuntimeCopyTCPConnection struct {
	reader    *bytes.Reader
	written   bytes.Buffer
	closed    bool
	closeOnce sync.Once
}

type optionalEmptyNetworkExtensionRuntimeCopyConnection struct {
	readPayloads [][]byte
	readIndex    int
	readErr      error
	writes       [][]byte
}

type doneSignalEmptyDownstreamConn struct {
	readPayloads [][]byte
	readIndex    int
	done         chan struct{}
	closeOnce    sync.Once
}

type delayedEmptyDownstreamNetConn struct {
	net.Conn
}

func (delayedEmptyDownstreamNetConn) AllowEmptyRuntimeCopyDownstream() bool {
	return true
}

type runtimeCopySessionTLSClientConn struct {
	t               *testing.T
	handler         http.Handler
	destinationHost string
	destinationPort int
	requestID       string
	applicationID   string
	mu              sync.Mutex
	opened          bool
	closed          bool
	exchanges       int
	readBuffer      bytes.Buffer
}

func newRuntimeCopySessionTLSClientConn(t *testing.T, handler http.Handler, destinationHost string, destinationPort int) *runtimeCopySessionTLSClientConn {
	t.Helper()
	return &runtimeCopySessionTLSClientConn{
		t:               t,
		handler:         handler,
		destinationHost: destinationHost,
		destinationPort: destinationPort,
		requestID:       "req-session-tls-probe-001",
		applicationID:   "default_network_extension_tunnel",
	}
}

func (conn *runtimeCopySessionTLSClientConn) Read(p []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.readBuffer.Len() > 0 {
		return conn.readBuffer.Read(p)
	}
	if conn.closed {
		return 0, io.EOF
	}
	return 0, timeoutNetworkExtensionRuntimeCopyError{}
}

func (conn *runtimeCopySessionTLSClientConn) Write(p []byte) (int, error) {
	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return 0, net.ErrClosed
	}
	operation := edgeplane.NetworkExtensionRuntimeCopySessionOperationExchange
	if !conn.opened {
		conn.opened = true
		operation = edgeplane.NetworkExtensionRuntimeCopySessionOperationOpen
	}
	conn.exchanges++
	conn.mu.Unlock()

	body := map[string]any{
		"schema_version":       edgeplane.NetworkExtensionRuntimeCopySessionRequestSchema,
		"tenant_id":            "tenant_lab_001",
		"request_id":           conn.requestID,
		"operation":            operation,
		"application_id":       conn.applicationID,
		"upstream_payload_b64": base64.StdEncoding.EncodeToString(p),
	}
	if operation == edgeplane.NetworkExtensionRuntimeCopySessionOperationOpen {
		body["destination_host"] = conn.destinationHost
		body["destination_port"] = conn.destinationPort
	}
	payload := postNetworkExtensionRuntimeCopySessionTestRequest(conn.t, conn.handler, body)
	if payload["status"] != "ok" {
		return 0, fmt.Errorf("session exchange status/category = %v/%v", payload["status"], payload["category"])
	}
	if downstreamPayloadBase64, ok := payload["downstream_payload_b64"]; ok {
		downstream, err := decodeBase64String(downstreamPayloadBase64)
		if err != nil {
			return 0, err
		}
		conn.mu.Lock()
		_, _ = conn.readBuffer.Write(downstream)
		conn.mu.Unlock()
	}
	if sessionClosed, _ := payload["session_closed"].(bool); sessionClosed {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
	}
	return len(p), nil
}

func (conn *runtimeCopySessionTLSClientConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.closed = true
	return nil
}

func (conn *runtimeCopySessionTLSClientConn) LocalAddr() net.Addr {
	return runtimeCopySessionTestAddr("client")
}

func (conn *runtimeCopySessionTLSClientConn) RemoteAddr() net.Addr {
	return runtimeCopySessionTestAddr("edge-session")
}

func (conn *runtimeCopySessionTLSClientConn) SetDeadline(time.Time) error {
	return nil
}

func (conn *runtimeCopySessionTLSClientConn) SetReadDeadline(time.Time) error {
	return nil
}

func (conn *runtimeCopySessionTLSClientConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (conn *runtimeCopySessionTLSClientConn) exchangeCount() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.exchanges
}

func (conn *runtimeCopySessionTLSClientConn) sessionClosedSeen() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closed
}

type runtimeCopySessionTestAddr string

func (addr runtimeCopySessionTestAddr) Network() string {
	return "runtime-copy-session-test"
}

func (addr runtimeCopySessionTestAddr) String() string {
	return string(addr)
}

type chunkedNetworkExtensionRuntimeCopyTCPConnection struct {
	*recordingNetworkExtensionRuntimeCopyTCPConnection
	mu           sync.Mutex
	readPayloads [][]byte
	readIndex    int
	writes       [][]byte
}

func newChunkedNetworkExtensionRuntimeCopyTCPConnection(readPayloads [][]byte) *chunkedNetworkExtensionRuntimeCopyTCPConnection {
	conn := &chunkedNetworkExtensionRuntimeCopyTCPConnection{readPayloads: readPayloads}
	conn.recordingNetworkExtensionRuntimeCopyTCPConnection = &recordingNetworkExtensionRuntimeCopyTCPConnection{}
	return conn
}

func (conn *chunkedNetworkExtensionRuntimeCopyTCPConnection) Read(p []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.readIndex >= len(conn.readPayloads) {
		return 0, io.EOF
	}
	payload := conn.readPayloads[conn.readIndex]
	conn.readIndex++
	return copy(p, payload), nil
}

func (conn *chunkedNetworkExtensionRuntimeCopyTCPConnection) Write(p []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.writes = append(conn.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (conn *chunkedNetworkExtensionRuntimeCopyTCPConnection) Close() error {
	conn.mu.Lock()
	conn.closed = true
	conn.mu.Unlock()
	return nil
}

func (conn *chunkedNetworkExtensionRuntimeCopyTCPConnection) writtenPayloads() [][]byte {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return append([][]byte(nil), conn.writes...)
}

func newRecordingNetworkExtensionRuntimeCopyTCPConnection(readPayload []byte) *recordingNetworkExtensionRuntimeCopyTCPConnection {
	return &recordingNetworkExtensionRuntimeCopyTCPConnection{reader: bytes.NewReader(readPayload)}
}

func (conn *recordingNetworkExtensionRuntimeCopyTCPConnection) Read(p []byte) (int, error) {
	return conn.reader.Read(p)
}

func (conn *recordingNetworkExtensionRuntimeCopyTCPConnection) Write(p []byte) (int, error) {
	return conn.written.Write(p)
}

func (conn *recordingNetworkExtensionRuntimeCopyTCPConnection) Close() error {
	conn.closeOnce.Do(func() {
		conn.closed = true
	})
	return nil
}

func (conn *optionalEmptyNetworkExtensionRuntimeCopyConnection) Read(p []byte) (int, error) {
	if conn.readIndex < len(conn.readPayloads) {
		payload := conn.readPayloads[conn.readIndex]
		conn.readIndex++
		return copy(p, payload), nil
	}
	if conn.readErr != nil {
		return 0, conn.readErr
	}
	return 0, timeoutNetworkExtensionRuntimeCopyError{}
}

func (conn *optionalEmptyNetworkExtensionRuntimeCopyConnection) Write(p []byte) (int, error) {
	conn.writes = append(conn.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (conn *optionalEmptyNetworkExtensionRuntimeCopyConnection) Close() error {
	return nil
}

func (conn *optionalEmptyNetworkExtensionRuntimeCopyConnection) AllowEmptyRuntimeCopyDownstream() bool {
	return true
}

func (conn *doneSignalEmptyDownstreamConn) Read(p []byte) (int, error) {
	if conn.readIndex < len(conn.readPayloads) {
		payload := conn.readPayloads[conn.readIndex]
		conn.readIndex++
		if conn.readIndex >= len(conn.readPayloads) {
			conn.closeOnce.Do(func() {
				close(conn.done)
			})
		}
		return copy(p, payload), nil
	}
	return 0, timeoutNetworkExtensionRuntimeCopyError{}
}

func (conn *doneSignalEmptyDownstreamConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (conn *doneSignalEmptyDownstreamConn) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.done)
	})
	return nil
}

func (conn *doneSignalEmptyDownstreamConn) AllowEmptyRuntimeCopyDownstream() bool {
	return true
}

func (conn *doneSignalEmptyDownstreamConn) RuntimeCopySessionDone() <-chan struct{} {
	return conn.done
}

type timeoutNetworkExtensionRuntimeCopyError struct{}

func (timeoutNetworkExtensionRuntimeCopyError) Error() string {
	return "runtime-copy optional downstream timeout"
}

func (timeoutNetworkExtensionRuntimeCopyError) Timeout() bool {
	return true
}

func (timeoutNetworkExtensionRuntimeCopyError) Temporary() bool {
	return true
}

// halfCloseWSUpstream is a controllable WebSocket origin: Read yields the origin->client response, Write records
// the client->origin bytes, and Close closes the response source. It deliberately does NOT expose CloseWrite — the
// tunnel must keep the origin streaming after a client half-close WITHOUT half-closing the origin socket (a TLS
// close_notify makes many WS servers stop streaming), so the fix must not depend on a CloseWrite capability.
type halfCloseWSUpstream struct {
	r io.Reader
	w io.Writer
}

func (u *halfCloseWSUpstream) Read(p []byte) (int, error)  { return u.r.Read(p) }
func (u *halfCloseWSUpstream) Write(p []byte) (int, error) { return u.w.Write(p) }

// wsRelaySink is a concurrency-safe origin write sink that also signals (via relayed) when the client's frame has
// actually been relayed upstream. The tunnel returns as soon as the ORIGIN direction finishes and deliberately
// does NOT wait for the client->origin copy goroutine (waiting would hang if the client is idle — see the leak
// guard), so a test that reads the sink right after the tunnel returns races that goroutine. Gating the origin's
// response on `relayed` both removes the race AND models real WS ordering: origin answers after it receives the
// client's frame.
type wsRelaySink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	once    sync.Once
	relayed chan struct{}
}

func (s *wsRelaySink) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	if n > 0 {
		s.once.Do(func() { close(s.relayed) })
	}
	return n, err
}

func (s *wsRelaySink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
func (u *halfCloseWSUpstream) Close() error {
	if c, ok := u.r.(io.Closer); ok {
		_ = c.Close()
	}
	return nil
}

// TestNetworkExtensionLabTLSWebSocketTunnelKeepsStreamingResponseAfterClientHalfClose is the regression guard for
// the Copilot-chat truncation: when the browser finishes/half-closes its send side (client->origin EOF), the
// tunnel must keep relaying the origin's still-streaming response instead of closing the origin and cutting it
// off. Previously the tunnel closed upstream on the first direction to end, so a clean client EOF truncated the
// chat answer (it shows "something went wrong, try sending a new message").
func TestNetworkExtensionLabTLSWebSocketTunnelKeepsStreamingResponseAfterClientHalfClose(t *testing.T) {
	const wantResponse = "STREAMED-CHAT-ANSWER-THAT-MUST-NOT-BE-TRUNCATED"

	downstreamReader := strings.NewReader("PING") // client sends one frame, then its send side EOFs.
	originRespR, originRespW := io.Pipe()         // origin -> client response source.
	clientToOrigin := &wsRelaySink{relayed: make(chan struct{})}
	upstream := &halfCloseWSUpstream{r: originRespR, w: clientToOrigin}
	var downstreamWriter bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- edgeplane.CopyNetworkExtensionLabTLSWebSocketTunnel(context.Background(), "test.example", 1, downstreamReader, &downstreamWriter, upstream)
	}()

	// Real WS ordering: the origin answers only after it has received the client's frame. Wait for the client->origin
	// relay to actually happen before streaming the origin's response — this also removes the race against the copy
	// goroutine (the tunnel returns on origin-close without waiting for it).
	select {
	case <-clientToOrigin.relayed:
	case <-time.After(2 * time.Second):
		t.Fatal("client->origin frame was not relayed upstream")
	}

	// Stream the origin's response AFTER the client has half-closed, then the origin closes the WS (EOF).
	if _, err := io.WriteString(originRespW, wantResponse); err != nil {
		t.Fatalf("write origin response: %v", err)
	}
	if err := originRespW.Close(); err != nil {
		t.Fatalf("close origin response: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tunnel returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not complete after the origin finished streaming")
	}

	if got := downstreamWriter.String(); got != wantResponse {
		t.Fatalf("origin->client response truncated: got %q want %q", got, wantResponse)
	}
	if got := clientToOrigin.String(); got != "PING" {
		t.Fatalf("client->origin relay: got %q want %q", got, "PING")
	}
}

// TestNetworkExtensionLabTLSWebSocketTunnelTearsDownWhenClientDisconnectsMidStream guards the leak that the
// half-close fix could introduce: after the client half-closes its send side, if the origin keeps the WS open
// but IDLE and the client then disconnects, the origin->client copy would block forever on upstream.Read,
// leaking the goroutine + origin connection (repeat Copilot chat sessions accumulated these and wedged the
// Edge). Cancelling the client context must tear the tunnel down.
func TestNetworkExtensionLabTLSWebSocketTunnelTearsDownWhenClientDisconnectsMidStream(t *testing.T) {
	downstreamReader := strings.NewReader("PING") // client sends one frame then half-closes (EOF)
	originRespR, _ := io.Pipe()                   // origin -> client: never fed, never closed (idle origin)
	upstream := &halfCloseWSUpstream{r: originRespR, w: &bytes.Buffer{}}
	var downstreamWriter bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- edgeplane.CopyNetworkExtensionLabTLSWebSocketTunnel(ctx, "test.example", 2, downstreamReader, &downstreamWriter, upstream)
	}()

	time.Sleep(200 * time.Millisecond) // let the half-close settle; the tunnel should still be up (origin idle)
	select {
	case <-done:
		t.Fatal("tunnel returned before the client disconnected — it must stay up while the origin holds the WS")
	default:
	}

	cancel() // client disconnects
	select {
	case <-done: // fixed: the context-cancel leak guard closed upstream, unblocking the idle origin->client read
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel LEAKED: did not tear down after the client disconnected while the origin was idle")
	}
}
