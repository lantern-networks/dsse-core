package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type failingApplicationConnectorLookup struct {
	*connector.Registry
	deviceID string
}

func (s failingApplicationConnectorLookup) GetByTenant(ctx context.Context, tenantID, id string) (model.ConnectorRegistration, bool, error) {
	if id == s.deviceID {
		return model.ConnectorRegistration{}, false, errors.New("injected connector lookup failure")
	}
	conn, found := s.Registry.Get(id)
	return conn, found && conn.TenantID == tenantID, nil
}

func (s failingApplicationConnectorLookup) ListByTenant(_ context.Context, tenantID string) ([]model.ConnectorRegistration, error) {
	var own []model.ConnectorRegistration
	for _, conn := range s.Registry.List() {
		if conn.TenantID == tenantID {
			own = append(own, conn)
		}
	}
	return own, nil
}

type failingApplicationDeviceLookup struct{ *device.Store }

func (s failingApplicationDeviceLookup) GetByTenant(string, string) (model.Device, bool, error) {
	return model.Device{}, false, errors.New("injected device lookup failure")
}

type secondApplicationDeviceLookupFails struct {
	*device.Store
	reads atomic.Int32
}

func (s *secondApplicationDeviceLookupFails) GetByTenant(tenantID, deviceID string) (model.Device, bool, error) {
	if s.reads.Add(1) > 1 {
		return model.Device{}, false, errors.New("injected second device lookup failure")
	}
	return s.Store.GetByTenant(tenantID, deviceID)
}

func TestConnectorGETDoesNotAcceptQueryIdentity(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "app_dummy_https"
	const connectorID = "conn_identity_boundary"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: connectorID, TenantID: tenant, ConnectorGroupID: "site",
		ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessions := session.NewStore()
	for _, user := range []string{"alice", "victim"} {
		if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{
			ID: "auth-" + user, SessionID: "sess-" + user, TenantID: tenant,
			UserID: user, Result: "success",
		}, "bundle", tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	boundOtherDevice := "another-device"
	if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID: "auth-bound-other", SessionID: "sess-bound-other", TenantID: tenant,
		UserID: "victim", DeviceID: &boundOtherDevice, Result: "success",
	}, "bundle", tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	policies := []model.Policy{{
		ID: "allow-victim", TenantID: tenant, Priority: 100,
		Conditions: map[string]any{"actor_type": "human", "application_id": app,
			"service_family": "https", "user_id": "victim"},
		Action: model.PolicyAction{Decision: "allow"}, Status: "active",
	}}
	proxied := 0
	ca := makeTestCA(t, t.TempDir(), "get-boundary", 191)
	caRegistry, err := tenantca.LoadTenantCARegistry(writeRegistry(t, t.TempDir(), map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "device-victim", caRegistry.Pool)
	devices := device.NewStore()
	if _, err := devices.Register(model.Device{ID: "device-victim", TenantID: tenant}, model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies(policies), Writer: writer,
		Registry: registry, SessionStore: sessions, LabMode: boolPtr(true),
		TenantCARegistry: caRegistry, DeviceStore: devices,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			proxied++
			return &http.Response{StatusCode: http.StatusOK,
				Header: http.Header{"content-type": []string{"text/plain"}},
				Body:   io.NopCloser(bytes.NewBufferString("private-app"))}, nil
		})},
	})
	request := func(sessionID string, verifiedDevice bool) int {
		r := httptest.NewRequest(http.MethodGet,
			"/apps/"+app+"?connector_id="+connectorID+"&user_id=victim&user_groups=admins", nil)
		if sessionID != "" {
			r.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
		}
		if verifiedDevice {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request("", false); got != http.StatusForbidden {
		t.Fatalf("anonymous caller claimed victim in query: status %d, want 403", got)
	}
	if got := request("sess-alice", true); got != http.StatusForbidden {
		t.Fatalf("alice session claimed victim in query: status %d, want 403", got)
	}
	if got := request("sess-victim", false); got != http.StatusForbidden {
		t.Fatalf("browser cookie on direct managed route: status %d, want 403", got)
	}
	if got := request("sess-bound-other", true); got != http.StatusForbidden {
		t.Fatalf("session bound to another device: status %d, want 403", got)
	}
	if got := request("sess-victim", true); got != http.StatusOK {
		t.Fatalf("victim session: status %d, want 200", got)
	}
	if proxied != 1 {
		t.Fatalf("private app proxy called %d times, want only verified victim flow", proxied)
	}
}

func TestClientlessSessionDeviceMetadataIsNotManagedProof(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "wiki-device-gated"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-device-gated", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	catalog := appcatalog.NewStore()
	if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{TenantID: tenant, ApplicationID: app, ApplicationType: "private_app", Status: "active", Published: true, Destination: "wiki.internal", DestinationPort: 443, PublishProtocol: "web"}, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	deviceID := "device-from-idp-session"
	sessions := session.NewStore()
	if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{ID: "auth-device-meta", SessionID: "sess-device-meta", TenantID: tenant, UserID: "user", DeviceID: &deviceID, Result: "success"}, "bundle", tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxied := false
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-device", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app, "device_id": deviceID}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, ApplicationCatalogStore: catalog, SessionStore: sessions, ClientlessAccessEnabled: true, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		proxied = true
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	r := httptest.NewRequest(http.MethodGet, "/clientless/apps/"+app, nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-device-meta"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || proxied {
		t.Fatalf("IdP session device metadata granted managed-device policy: status=%d proxied=%v", w.Code, proxied)
	}
}

func TestDirectGETDoesNotLetQuerySessionOverrideCookie(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "app_dummy_https"
	ca := makeTestCA(t, t.TempDir(), "get-cookie", 192)
	otherCA := makeTestCA(t, t.TempDir(), "get-other-tenant", 194)
	caRegistry, err := tenantca.LoadTenantCARegistry(writeRegistry(t, t.TempDir(), map[string]string{tenant: ca.pemPath, "tenant_other": otherCA.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "device-alice", caRegistry.Pool)
	foreignChains := leafSignedBy(t, otherCA, "device-other", caRegistry.Pool)
	connectorChains := leafSignedBy(t, ca, "conn-cookie", caRegistry.Pool)
	devices := device.NewStore()
	if _, err := devices.Register(model.Device{ID: "device-alice", TenantID: tenant}, model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Register(model.Device{ID: "device-other", TenantID: "tenant_other"}, model.PolicyBundle{TenantID: "tenant_other"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Register(model.Device{ID: "conn-cookie", TenantID: tenant}, model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-cookie", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	sessions := session.NewStore()
	for _, user := range []string{"alice", "victim"} {
		if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{ID: "auth-" + user, SessionID: "sess-" + user, TenantID: tenant, UserID: user, Result: "success"}, "bundle", tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-alice", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app, "user_id": "alice"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, SessionStore: sessions, TenantCARegistry: caRegistry, DeviceStore: devices, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	r := httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-cookie&session_id=sess-victim", nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-alice"})
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("query session overrode verified cookie: %d, want 200", w.Code)
	}
	for _, tc := range []struct {
		name   string
		chains [][]*x509.Certificate
	}{{"foreign tenant", foreignChains}, {"connector certificate", connectorChains}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-cookie", nil)
			bad.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-alice"})
			bad.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.chains[0][0]}, VerifiedChains: tc.chains}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, bad)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s used Alice session: %d, want 403", tc.name, w.Code)
			}
		})
	}
}

func TestManagedApplicationDeviceUsesCertificateTenantAcrossFleet(t *testing.T) {
	const app = "private-b"
	caA := makeTestCA(t, t.TempDir(), "fleet-a", 195)
	caB := makeTestCA(t, t.TempDir(), "fleet-b", 196)
	regCA, err := tenantca.LoadTenantCARegistry(writeRegistry(t, t.TempDir(), map[string]string{"tenant_lab_001": caA.pemPath, "tenant_b": caB.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, caB, "device-b", regCA.Pool)
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-b", TenantID: "tenant_b", ConnectorGroupID: "site-b", ApplicationIDs: []string{app}, PrivateBaseURL: "http://tenant-b.invalid", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	devices := device.NewStore()
	if _, err := devices.Register(model.Device{ID: "device-b", TenantID: "tenant_b"}, model.PolicyBundle{TenantID: "tenant_b"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-b-managed", TenantID: "tenant_b", Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app, "source_role": "managed_endpoint"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, DeviceStore: devices, TenantCARegistry: regCA, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	r := httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-b", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("tenant B managed device on seed A node: %d, want 200", w.Code)
	}
	if _, err := devices.Register(model.Device{ID: "device-b", TenantID: "tenant_b", Status: "revoked"}, model.PolicyBundle{TenantID: "tenant_b"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked device retained managed endpoint authority: %d, want 403", w.Code)
	}
}

func TestManagedApplicationAuthorityReadErrorsFailClosed(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "private-read-error"
	ca := makeTestCA(t, t.TempDir(), "authority-failure", 197)
	regCA, err := tenantca.LoadTenantCARegistry(writeRegistry(t, t.TempDir(), map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "device-read-error", regCA.Pool)
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-read-error", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.invalid", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	devices := device.NewStore()
	if _, err := devices.Register(model.Device{ID: "device-read-error", TenantID: tenant}, model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		registry connectorRegistryStore
		devices  deviceRuntimeStore
	}{{"connector", failingApplicationConnectorLookup{Registry: registry, deviceID: "device-read-error"}, devices}, {"device", registry, failingApplicationDeviceLookup{Store: devices}}} {
		t.Run(tc.name, func(t *testing.T) {
			proxied := false
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-managed", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app, "source_role": "managed_endpoint"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: tc.registry, DeviceStore: tc.devices, TenantCARegistry: regCA, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				proxied = true
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
			})}})
			r := httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-read-error", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable || proxied {
				t.Fatalf("%s authority read failure: status=%d proxied=%v", tc.name, w.Code, proxied)
			}
		})
	}
}

func TestManagedApplicationRiskUsesVerifiedDeviceSnapshot(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "risk-private-app"
	ca := makeTestCA(t, t.TempDir(), "risk-snapshot", 198)
	regCA, err := tenantca.LoadTenantCARegistry(writeRegistry(t, t.TempDir(), map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "device-risk", regCA.Pool)
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-risk", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.invalid", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	backing := device.NewStore()
	if _, err := backing.Register(model.Device{ID: "device-risk", TenantID: tenant}, model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok, _, err := backing.ApplyRiskSignal("device-risk", model.RiskSignal{EntityType: "device", EntityID: "device-risk", Severity: "high", Source: "admin"}, time.Now()); err != nil || !ok {
		t.Fatalf("apply risk: ok=%v err=%v", ok, err)
	}
	devices := &secondApplicationDeviceLookupFails{Store: backing}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxied := false
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "deny-high", TenantID: tenant, Priority: 10, Conditions: map[string]any{"application_id": app, "risk_state_severity": []any{"high", "critical"}}, Action: model.PolicyAction{Decision: "deny"}, Status: "active"}, {ID: "allow-app", TenantID: tenant, Priority: 100, Conditions: map[string]any{"application_id": app}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, DeviceStore: devices, TenantCARegistry: regCA, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		proxied = true
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	r := httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-risk", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || proxied {
		t.Fatalf("risk snapshot lost after second read error: status=%d proxied=%v reads=%d", w.Code, proxied, devices.reads.Load())
	}
}

func TestClientlessSessionTenantSelectsItsOwnConnector(t *testing.T) {
	const app = "wiki"
	registry := connector.NewRegistry()
	register := func(id, tenant, host string) {
		t.Helper()
		if _, err := registry.Register(model.ConnectorRegistration{
			ID: id, TenantID: tenant, ConnectorGroupID: "site-" + tenant,
			ApplicationIDs: []string{app}, PrivateBaseURL: "http://" + host, Status: "registered",
		}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	register("conn-a", "tenant_lab_001", "tenant-a.invalid")
	catalog := appcatalog.NewStore()
	for _, tenant := range []string{"tenant_lab_001", "tenant_b"} {
		if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{
			TenantID: tenant, ApplicationID: app, ApplicationType: "private_app",
			Status: "active", Published: true, Destination: "wiki.internal.invalid",
			DestinationPort: 8080, PublishProtocol: "web",
		}, tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	sessions := session.NewStore()
	for _, tc := range []struct{ tenant, user, session string }{{"tenant_lab_001", "user-a", "sess-a"}, {"tenant_b", "user-b", "sess-b"}} {
		if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{
			ID: "auth-" + tc.user, SessionID: tc.session, TenantID: tc.tenant,
			UserID: tc.user, Result: "success",
		}, "bundle", tc.tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proxied := []string{}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies([]model.Policy{
			{
				ID: "public-a", TenantID: "tenant_lab_001", Priority: 100,
				Conditions: map[string]any{"actor_type": "human", "application_id": app},
				Action:     model.PolicyAction{Decision: "allow"}, Status: "active",
			},
			{
				ID: "user-b", TenantID: "tenant_b", Priority: 100,
				Conditions: map[string]any{"actor_type": "human", "application_id": app, "user_id": "user-b"},
				Action:     model.PolicyAction{Decision: "allow"}, Status: "active",
			},
		}),
		Writer: writer, Registry: registry, SessionStore: sessions,
		ApplicationCatalogStore: catalog, ClientlessAccessEnabled: true, LabMode: boolPtr(true),
		ProxyClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			proxied = append(proxied, r.URL.Host)
			return &http.Response{StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewBufferString("app"))}, nil
		})},
	})
	request := func() int {
		r := httptest.NewRequest(http.MethodGet, "/clientless/apps/"+app+"?session_id=sess-a", nil)
		r.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-b"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request(); got != http.StatusNotFound {
		t.Fatalf("tenant B with no B connector got status %d, want 404", got)
	}
	if len(proxied) != 0 {
		t.Fatalf("tenant B request was proxied into tenant A: %#v", proxied)
	}
	register("conn-b", "tenant_b", "tenant-b.invalid")
	if got := request(); got != http.StatusOK {
		t.Fatalf("tenant B own connector got status %d, want 200", got)
	}
	if len(proxied) != 1 || proxied[0] != "tenant-b.invalid" {
		t.Fatalf("tenant B routed to %#v, want tenant-b.invalid only", proxied)
	}
}

func TestUnpublishedActiveAppIsNotClientless(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "unpublished-wiki"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-unpublished", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	catalog := appcatalog.NewStore()
	if _, err := catalog.Upsert(context.Background(), appcatalog.Entry{TenantID: tenant, ApplicationID: app, ApplicationType: "private_app", Status: "active", Published: false}, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	sessions := session.NewStore()
	if _, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{ID: "auth-u", SessionID: "sess-u", TenantID: tenant, UserID: "user-u", Result: "success"}, "bundle", tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, SessionStore: sessions, ApplicationCatalogStore: catalog, ClientlessAccessEnabled: true, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	r := httptest.NewRequest(http.MethodGet, "/clientless/apps/"+app, nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-u"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unpublished active app reached clientless relay: %d, want 403", w.Code)
	}
}

func TestConnectorGETKeepsExplicitPublicPolicy(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "app_dummy_https"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_public", TenantID: tenant, ConnectorGroupID: "site",
		ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies([]model.Policy{{
			ID: "allow-public", TenantID: tenant, Priority: 100,
			Conditions: map[string]any{"actor_type": "human", "application_id": app,
				"service_family": "https"},
			Action: model.PolicyAction{Decision: "allow"}, Status: "active",
		}}),
		Writer: writer, Registry: registry, LabMode: boolPtr(true),
		ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
		})},
	})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/apps/"+app+"?connector_id=conn_public", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("explicit public policy: status %d, want 200", w.Code)
	}
}

func TestAnonymousApplicationRequestCannotClaimManagedEndpoint(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "app_dummy_https"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-managed", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]edgeplane.ApplicationRouteProfile{app: {Destination: "internal.example", DestinationPort: 443, Protocol: "tcp", ServiceFamily: "https", ApplicationSensitivity: "high"}}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-managed", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app, "source_role": "managed_endpoint"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, RouteProfiles: profiles, LabMode: boolPtr(true)})
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		r := httptest.NewRequest(method, "/apps/"+app+"?connector_id=conn-managed", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("anonymous %s gained managed endpoint role: %d, want 403", method, w.Code)
		}
	}
}

func TestAnonymousHighSensitivityApplicationIsNotPublic(t *testing.T) {
	const tenant = "tenant_lab_001"
	const app = "app_dummy_https"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-high", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{app}, PrivateBaseURL: "http://connector.local", Status: "registered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies([]model.Policy{{ID: "allow-public", TenantID: tenant, Priority: 100, Conditions: map[string]any{"actor_type": "human", "application_id": app}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}), Writer: writer, Registry: registry, RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{app: {Destination: "internal.example", DestinationPort: 443, Protocol: "tcp", ServiceFamily: "https", ApplicationSensitivity: "high"}}, LabMode: boolPtr(true), ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil
	})}})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/"+app+"?connector_id=conn-high", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("anonymous public policy reached high sensitivity app: %d, want 403", w.Code)
	}
}
