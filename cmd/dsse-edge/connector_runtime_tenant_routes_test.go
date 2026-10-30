package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestConnectorRuntimeRoutesUseCertificateTenantAcrossFleet(t *testing.T) {
	const seed, other = "tenant_lab_001", "tenant_other"
	dir := t.TempDir()
	caSeed := makeTestCA(t, dir, "runtime-tenant-seed", 81)
	caOther := makeTestCA(t, dir, "runtime-tenant-other", 82)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{
		seed: caSeed.pemPath, other: caOther.pemPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	chains := map[string][][]*x509.Certificate{
		seed:  leafSignedBy(t, caSeed, "conn-seed", reg.Pool),
		other: leafSignedBy(t, caOther, "conn-other", reg.Pool),
	}
	for tenant, chain := range chains {
		if len(chain) == 0 {
			t.Fatalf("%s certificate did not verify", tenant)
		}
	}
	sessions := session.NewStore()
	for _, tenant := range []string{seed, other} {
		_, err := sessions.CreateFromAuthenticationEvent(model.AuthenticationEvent{
			ID: "auth-" + tenant, SessionID: "sess-" + tenant, TenantID: tenant,
			UserID: "user-" + tenant, Result: "success",
		}, "bundle", "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	devices := device.NewStore()
	for _, tenant := range []string{seed, other} {
		if _, err := devices.Register(model.Device{ID: "dev-" + tenant, TenantID: tenant},
			model.PolicyBundle{TenantID: tenant}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	approvals := humanapproval.NewStore(0)
	grants := delegatedgrant.NewStore(0)
	for _, tenant := range []string{seed, other} {
		if _, err := approvals.Upsert(model.HumanApprovalEvent{ID: "shared-approval", TenantID: tenant}); err != nil {
			t.Fatal(err)
		}
		if _, err := grants.Upsert(model.DelegatedAccessGrant{ID: "shared-grant", TenantID: tenant, Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		SessionStore: sessions, DeviceStore: devices, HumanApprovals: approvals,
		DelegatedGrants: grants, TenantCARegistry: reg, LabMode: boolPtr(false),
	})
	request := func(tenant, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set(connectorIDHeader, map[string]string{seed: "conn-seed", other: "conn-other"}[tenant])
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[tenant][0][0]}, VerifiedChains: chains[tenant]}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	// A certificate for the caller's own tenant plus an explicit own tenant
	// body must not import another tenant's user or MFA via a session ID.
	wSession := request(other, http.MethodPost, "/decisions/evaluate", `{"tenant_id":"tenant_other","session_id":"sess-tenant_lab_001"}`)
	if wSession.Code != http.StatusOK {
		t.Fatalf("decision with unrelated session: %d", wSession.Code)
	}
	if strings.Contains(wSession.Body.String(), "user-"+seed) || strings.Contains(wSession.Body.String(), "auth-"+seed) {
		t.Fatal("runtime decision disclosed another tenant's session identity")
	}
	// A connector certificate for another tenant must not claim the seed tenant
	// in an authentication event. A valid event for its own tenant must work on
	// this Edge, but it must not replace a browser session from the seed tenant
	// by reusing its session ID.
	if w := request(other, http.MethodPost, "/auth/events", `{"id":"auth-forged-seed","session_id":"forged-seed","tenant_id":"tenant_lab_001","user_id":"forged-user","result":"success"}`); w.Code < 400 {
		t.Fatalf("other tenant forged seed authentication event: %d", w.Code)
	}
	if _, ok := sessions.Get("forged-seed"); ok {
		t.Fatal("forged seed authentication event created a session")
	}
	if w := request(other, http.MethodPost, "/auth/events", `{"id":"auth-forged-existing","session_id":"sess-tenant_lab_001","tenant_id":"tenant_lab_001","user_id":"forged-user","result":"success"}`); w.Code < 400 {
		t.Fatalf("other tenant replaced seed browser session: %d", w.Code)
	}
	if w := request(other, http.MethodPost, "/auth/events", `{"id":"auth-other-valid","session_id":"other-valid","tenant_id":"tenant_other","user_id":"other-user","result":"success"}`); w.Code != http.StatusCreated {
		t.Fatalf("own-tenant authentication event: %d %s", w.Code, w.Body.String())
	}
	if w := request(other, http.MethodPost, "/auth/events", `{"id":"auth-other-collision","session_id":"sess-tenant_lab_001","tenant_id":"tenant_other","user_id":"other-user","result":"success"}`); w.Code < 400 {
		t.Fatalf("other tenant replaced seed session by ID: %d", w.Code)
	}
	seedCookieRequest := httptest.NewRequest(http.MethodGet, "/clientless/apps/sample", nil)
	seedCookieRequest.AddCookie(&http.Cookie{Name: "session_id", Value: "sess-" + seed})
	if sess, ok := activeSessionFromRequest(seedCookieRequest, sessions); !ok || sess.TenantID != seed || sess.UserID != "user-"+seed {
		t.Fatalf("seed browser cookie changed tenant after other tenant event: %+v, active=%v", sess, ok)
	}
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/sessions/sess-" + seed, http.StatusNotFound},
		{"/sessions/sess-" + other, http.StatusOK},
		{"/devices/dev-" + seed, http.StatusNotFound},
		{"/devices/dev-" + other, http.StatusOK},
		{"/devices/dev-" + seed + "/agent-rollout", http.StatusNotFound},
		{"/devices/dev-" + other + "/agent-rollout", http.StatusOK},
		{"/devices/dev-" + seed + "/policy-bundle", http.StatusNotFound},
		{"/devices/dev-" + seed + "/trusted-keyring", http.StatusNotFound},
		{"/human-approvals/events/shared-approval", http.StatusOK},
		{"/delegated-grants/shared-grant", http.StatusOK},
	} {
		w := request(other, http.MethodGet, tc.path, "")
		if w.Code != tc.want {
			t.Fatalf("other tenant GET %s: status %d, want %d: %s", tc.path, w.Code, tc.want, w.Body.String())
		}
		if tc.want == http.StatusOK {
			var value struct {
				TenantID string `json:"tenant_id"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil || value.TenantID != other {
				t.Fatalf("GET %s returned wrong tenant: %+v %v", tc.path, value, err)
			}
		}
	}
	w := request(other, http.MethodGet, "/devices", "")
	if w.Code != http.StatusOK {
		t.Fatalf("other tenant device list: %d %s", w.Code, w.Body.String())
	}
	var listed []model.Device
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 1 || listed[0].TenantID != other {
		t.Fatalf("device list mixed tenants: %+v %v", listed, err)
	}
	if w := request(other, http.MethodPost, "/human-approvals/events", `{"id":"claimed-a","tenant_id":"tenant_lab_001"}`); w.Code < 400 {
		t.Fatalf("cross-tenant approval write accepted: %d", w.Code)
	}
	if _, ok := approvals.GetForTenant(seed, "claimed-a"); ok {
		t.Fatal("cross-tenant approval stored")
	}
	if w := request(other, http.MethodPost, "/delegated-grants", `{"id":"claimed-a","tenant_id":"tenant_lab_001"}`); w.Code < 400 {
		t.Fatalf("cross-tenant grant write accepted: %d", w.Code)
	}
	if _, ok := grants.GetForTenant(seed, "claimed-a"); ok {
		t.Fatal("cross-tenant grant stored")
	}
	if w := request(other, http.MethodPost, "/devices/register", `{"id":"dev-tenant_lab_001","tenant_id":"tenant_lab_001"}`); w.Code < 400 {
		t.Fatalf("cross-tenant device registration accepted: %d", w.Code)
	}
	if dev, ok := devices.Get("dev-" + seed); !ok || dev.TenantID != seed {
		t.Fatalf("cross-tenant device registration replaced seed device: %+v, found=%v", dev, ok)
	}
	if w := request(other, http.MethodPost, "/devices/dev-"+seed+"/agent-status", `{"device_id":"dev-tenant_lab_001"}`); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant agent status accepted: %d", w.Code)
	}
	if w := request(other, http.MethodPost, "/tools/events", `{"id":"claimed-a","tenant_id":"tenant_lab_001"}`); w.Code < 400 {
		t.Fatalf("cross-tenant tool event accepted: %d", w.Code)
	}
	if w := request(other, http.MethodPost, "/east-west/grant", `{"challenge_id":"ewc_0123456789abcdef0123456789abcdef"}`); w.Code != http.StatusForbidden {
		t.Fatalf("fleet connector minted a grant from a bare challenge ID: %d", w.Code)
	}
	w = request(other, http.MethodPost, "/delegated-grants/shared-grant/revoke", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("own grant revoke: %d %s", w.Code, w.Body.String())
	}
	if own, _ := grants.GetForTenant(seed, "shared-grant"); own.Status != "active" {
		t.Fatal("other tenant revoked seed grant")
	}
}
