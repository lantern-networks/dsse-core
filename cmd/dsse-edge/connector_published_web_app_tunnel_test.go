package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// fakeTCPConnector is a minimal stand-in for the dsse-connector tunnel peer: it reads tunnel frames from the
// connector side of an in-process tunnel, dials the published destination on FrameTCPOpen, and pumps raw bytes
// between that backend TCP connection and the tunnel (down-frames for backend->edge, applying up-frames for
// edge->backend). It is intentionally tiny — the real connector's reachable_routes authorization is exercised
// by the real-binary CONNECT E2E; here we only need a frame-faithful peer to prove the edge's HTTP-over-CONNECT
// web data path reaches the published destination.
func fakeTCPConnector(t *testing.T, conn *tunnel.Conn, backendAddr string) {
	t.Helper()
	var writeMu sync.Mutex
	write := func(frame tunnel.Frame) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteJSON(frame)
	}
	backends := map[string]net.Conn{}
	var mu sync.Mutex
	go func() {
		for {
			var frame tunnel.Frame
			if err := conn.ReadJSON(&frame); err != nil {
				return
			}
			switch frame.Type {
			case tunnel.FrameTCPOpen:
				backend, err := net.Dial("tcp", backendAddr)
				if err != nil {
					write(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID, Error: err.Error()})
					continue
				}
				mu.Lock()
				backends[frame.RequestID] = backend
				mu.Unlock()
				write(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID})
				go func(requestID string, backend net.Conn) {
					buf := make([]byte, 32*1024)
					for {
						n, err := backend.Read(buf)
						if n > 0 {
							dataFrame, derr := tunnel.NewTCPDataFrame(requestID, tunnel.TCPDirectionDown, buf[:n])
							if derr == nil {
								write(dataFrame)
							}
						}
						if err != nil {
							write(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: requestID, Direction: tunnel.TCPDirectionDown, CloseReason: tunnel.TCPCloseReasonEOF})
							return
						}
					}
				}(frame.RequestID, backend)
			case tunnel.FrameTCPData:
				mu.Lock()
				backend := backends[frame.RequestID]
				mu.Unlock()
				if backend != nil {
					if payload, err := tunnel.TCPDataFramePayload(frame); err == nil {
						_, _ = backend.Write(payload)
					}
				}
			case tunnel.FrameTCPClose:
				mu.Lock()
				backend := backends[frame.RequestID]
				delete(backends, frame.RequestID)
				mu.Unlock()
				if backend != nil {
					_ = backend.Close()
				}
			}
		}
	}()
}

// TestPublishedWebAppGETReachesDestinationViaTunnel proves the fix: a GET /apps/{id} for a PUBLISHED web
// private app is proxied over the connector tunnel's CONNECT (FrameTCPOpen) path to the PUBLISHED destination
// and returns the real backend body — not the connector's privateBaseURL. Published != Allow (an allow policy
// is required), tenant-scoped, fail-closed.
func TestPublishedWebAppGETReachesDestinationViaTunnel(t *testing.T) {
	const tenant = "tenant_lab_001"
	const appID = "app_pub_web_tunnel_001"
	const connID = "conn_pub_web_001"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "HELLO-PUBLISHED-WEB-APP")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	backendHost, _, _ := net.SplitHostPort(backendAddr)
	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: connID, TenantID: tenant, ConnectorGroupID: "cgrp_lab_001", Name: "Lab Connector",
		EdgeRegionID: "local", EdgeClusterID: "local-edge-001", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", Status: "registered", Metadata: map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// In-process tunnel between the edge session and the fake connector peer.
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	tunnelManager := tunnel.NewManagerWithRequestTimeout(2 * time.Second)
	session, _ := tunnelManager.Register(connID, "tun_pub_web_001", tunnel.NewInProcessConn(clientRaw, true))
	go func() { _ = session.Run() }()
	fakeTCPConnector(t, tunnel.NewInProcessConn(serverRaw, false), backendAddr)

	// Publish the web app pointing at the real backend host:port (creates reachability only).
	catalog := appcatalog.NewStore()
	if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{
		ApplicationID:    appID,
		TenantID:         tenant,
		Name:             "Internal Web",
		ApplicationType:  "private_app",
		Destination:      backendHost,
		DestinationPort:  backendPort,
		PublishProtocol:  "web",
		ConnectorGroupID: "cgrp_lab_001",
		Published:        true,
		Status:           "active",
	}, tenant, time.Now()); err != nil {
		t.Fatalf("publish web app: %v", err)
	}

	// Allow policy bound to the app (Published != Allow: without it the flow denies). Leaving PolicyStore nil
	// makes newServerWithConfig seed the runtime store from these evaluator policies.
	evaluator := testEvaluatorWithPolicies([]model.Policy{{
		ID:       "pol_pub_web_allow_001",
		TenantID: tenant,
		Priority: 100,
		Conditions: map[string]any{
			"actor_type":     "human",
			"application_id": appID,
		},
		Action: model.PolicyAction{Decision: "allow"},
		Status: "active",
	}})

	handler := newServerWithConfig(serverConfig{
		Evaluator:               evaluator,
		Writer:                  writer,
		Registry:                registry,
		TunnelManager:           tunnelManager,
		ApplicationCatalogStore: catalog,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatalf("legacy privateBaseURL proxy client must NOT be called for a published web app")
			return nil, nil
		})},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/apps/"+appID+"?connector_id="+connID, nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("published web app GET status = %d (want 200); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "HELLO-PUBLISHED-WEB-APP") {
		t.Fatalf("published web app GET body = %q, want the real backend body", rec.Body.String())
	}

	// Audit: a web-session-started event over the tunnel path is recorded; it must not leak the privateBaseURL.
	auditRaw, err := os.ReadFile(filepath.Join(writer.Dir(), "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector audit log: %v", err)
	}
	auditBytes := string(auditRaw)
	if !strings.Contains(auditBytes, "private_app_web_session_started") {
		t.Fatalf("connector audit missing private_app_web_session_started event: %s", auditBytes)
	}
	if strings.Contains(auditBytes, "connector.local") {
		t.Fatalf("connector audit leaked privateBaseURL: %s", auditBytes)
	}
}

// TestPublishedWebAppGETIsNotAllow verifies Published != Allow on the web tunnel path: with NO policy the
// published web app GET is denied (it never reaches the backend).
func TestPublishedWebAppGETIsNotAllow(t *testing.T) {
	const tenant = "tenant_lab_001"
	const appID = "app_pub_web_denied_001"
	const connID = "conn_pub_web_denied_001"

	backendDialed := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendDialed = true
		_, _ = io.WriteString(w, "SHOULD-NOT-REACH")
	}))
	defer backend.Close()
	backendHost, _, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: connID, TenantID: tenant, ConnectorGroupID: "cgrp_lab_001", Name: "Lab Connector",
		EdgeRegionID: "local", EdgeClusterID: "local-edge-001", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", Status: "registered", Metadata: map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	tunnelManager := tunnel.NewManagerWithRequestTimeout(2 * time.Second)
	session, _ := tunnelManager.Register(connID, "tun_pub_web_denied_001", tunnel.NewInProcessConn(clientRaw, true))
	go func() { _ = session.Run() }()
	fakeTCPConnector(t, tunnel.NewInProcessConn(serverRaw, false), net.JoinHostPort(backendHost, "0"))

	catalog := appcatalog.NewStore()
	if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{
		ApplicationID: appID, TenantID: tenant, Name: "Internal Web", ApplicationType: "private_app",
		Destination: backendHost, DestinationPort: backendPort, PublishProtocol: "web",
		ConnectorGroupID: "cgrp_lab_001", Published: true, Status: "active",
	}, tenant, time.Now()); err != nil {
		t.Fatalf("publish web app: %v", err)
	}

	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluatorWithPolicies(nil), // no allow policy -> default deny
		Writer:                  writer,
		Registry:                registry,
		TunnelManager:           tunnelManager,
		ApplicationCatalogStore: catalog,
		PolicyStore:             policy.NewStore(nil),
		ProxyClient:             &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })},
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apps/"+appID+"?connector_id="+connID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized published web app GET status = %d, want 403 (Published != Allow)", rec.Code)
	}
	if backendDialed {
		t.Fatalf("denied flow must NOT reach the backend")
	}
}
