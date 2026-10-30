package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type secondReadFailCatalog struct {
	appcatalog.RuntimeStore
	gets atomic.Int32
}

func (s *secondReadFailCatalog) Get(ctx context.Context, tenantID, applicationID string) (appcatalog.Entry, bool, error) {
	if s.gets.Add(1) == 2 {
		return appcatalog.Entry{}, false, errors.New("injected second catalog read failure")
	}
	return s.RuntimeStore.Get(ctx, tenantID, applicationID)
}

func TestPublishedApplicationSecondCatalogReadFailureDoesNotFallBackToLegacyTunnel(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "published-wiki"
	const connID = "conn-published"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: connID, TenantID: tenant, ConnectorGroupID: "site",
		ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	baseCatalog := appcatalog.NewStore()
	if _, err := baseCatalog.Upsert(context.Background(), appcatalog.Entry{
		TenantID: tenant, ApplicationID: app, ApplicationType: "private_app", Status: "active",
		Published: true, Destination: "wiki.internal.example", DestinationPort: 8080,
		PublishProtocol: "web",
	}, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	catalog := &secondReadFailCatalog{RuntimeStore: baseCatalog}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	manager := tunnel.NewManagerWithRequestTimeout(time.Second)
	session, _ := manager.Register(connID, "tun_second_read", tunnel.NewInProcessConn(clientRaw, true))
	go func() { _ = session.Run() }()
	observed := make(chan string, 1)
	go func() {
		peer := tunnel.NewInProcessConn(serverRaw, false)
		var frame tunnel.Frame
		if err := peer.ReadJSON(&frame); err != nil {
			return
		}
		observed <- frame.Type
		if frame.Type == tunnel.FrameHTTPRequest {
			_ = peer.WriteJSON(tunnel.Frame{Type: tunnel.FrameHTTPResponse,
				RequestID: frame.RequestID, StatusCode: http.StatusOK, Body: "legacy-path"})
		}
	}()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies([]model.Policy{{
			ID: "allow-published", TenantID: tenant, Priority: 100,
			Conditions: map[string]any{"actor_type": "human", "application_id": app},
			Action:     model.PolicyAction{Decision: "allow"}, Status: "active",
		}}),
		Writer: writer, Registry: registry, ApplicationCatalogStore: catalog,
		TunnelManager: manager, LabMode: boolPtr(true),
	})
	catalog.gets.Store(0)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/apps/"+app+"?connector_id="+connID, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("second catalog read failed but route status = %d, want 503; legacy tunnel may have been used", w.Code)
	}
	select {
	case frameType := <-observed:
		t.Fatalf("catalog failure emitted tunnel frame %q, want none", frameType)
	default:
	}
}
