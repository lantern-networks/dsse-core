package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/internalca"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type internalCAFaultStore struct {
	rows []internalca.Authority
	fail bool
}

func (p *internalCAFaultStore) LoadAll() ([]internalca.Authority, error) {
	return append([]internalca.Authority(nil), p.rows...), nil
}
func (p *internalCAFaultStore) Upsert(a internalca.Authority) error {
	if p.fail {
		return fmt.Errorf("private-storage-location")
	}
	for i, v := range p.rows {
		if v.ID == a.ID && v.TenantID == a.TenantID {
			p.rows[i] = a
			return nil
		}
	}
	p.rows = append(p.rows, a)
	return nil
}
func (p *internalCAFaultStore) Delete(id, tenant string) error {
	if p.fail {
		return fmt.Errorf("private-storage-location")
	}
	next := []internalca.Authority{}
	for _, a := range p.rows {
		if a.ID != id || a.TenantID != tenant {
			next = append(next, a)
		}
	}
	p.rows = next
	return nil
}
func TestInternalCAHTTPPersistenceAuditAndTenantBoundary(t *testing.T) {
	now := time.Now()
	oldOperator := operatorTenantConfigured()
	operatorTenantAuthority.Store("")
	t.Cleanup(func() { operatorTenantAuthority.Store(oldOperator) })
	p := &internalCAFaultStore{}
	s, _ := internalca.NewStore(p)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	for _, role := range []string{"admin", "analyst"} {
		auth.UpsertPrincipal(adminPrincipal{ID: role, TenantID: "tenant_lab_001", Roles: []string{role}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: role, TokenHash: adminTokenHash("private-" + role), TenantID: "tenant_lab_001", Roles: []string{role}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: role, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, InternalCAs: s})
	call := func(method, path, body, role string, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if role != "" {
			req.Header.Set("Authorization", "Bearer private-"+role)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s %s = %d want %d: %s", method, path, w.Code, status, w.Body)
		}
		if strings.Contains(w.Body.String(), "private-storage-location") {
			t.Fatal("storage detail leaked")
		}
		return w
	}
	a := internalca.Authority{ID: "own", TenantID: "tenant_lab_001", Name: "private-name", CertificatePEM: anInternalAuthorityPEM(t, "private-ca-subject")}
	foreign := a
	foreign.ID = "foreign"
	foreign.TenantID = "tenant_other"
	s.Upsert(foreign, now)
	body, _ := json.Marshal(a)
	call("POST", "/admin/internal-cas", string(body), "analyst", 403)
	call("POST", "/admin/internal-cas", string(body), "", 401)
	p.fail = true
	call("POST", "/admin/internal-cas", string(body), "admin", 500)
	if len(s.List(a.TenantID, now)) != 0 {
		t.Fatal("failed add adopted")
	}
	p.fail = false
	call("POST", "/admin/internal-cas", string(body), "admin", 200)
	p.fail = true
	call("DELETE", "/admin/internal-cas/own", "", "admin", 500)
	if len(s.List(a.TenantID, now)) != 1 {
		t.Fatal("failed delete adopted")
	}
	p.fail = false
	call("GET", "/admin/internal-cas/all", "", "admin", 403)
	call("GET", "/admin/internal-cas?tenant_id=tenant_other", "", "admin", 403)
	call("DELETE", "/admin/internal-cas/foreign", "", "admin", 404)
	mixed := a
	mixed.ID = "mixed"
	mixed.CertificatePEM += "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----"
	b, _ := json.Marshal(mixed)
	call("POST", "/admin/internal-cas", string(b), "admin", 400)
	call("POST", "/admin/internal-cas", string(body)+" {}", "admin", 400)
	w := call("DELETE", "/admin/internal-cas/own", "", "admin", 200)
	var deleted map[string]any
	json.Unmarshal(w.Body.Bytes(), &deleted)
	if deleted["deleted"] != true || deleted["id"] != "own" || deleted["tenant_id"] != a.TenantID {
		t.Fatal("delete not identified")
	}
	restarted, e := internalca.NewStore(p)
	if e != nil || len(restarted.List(a.TenantID, now)) != 0 || len(restarted.List("tenant_other", now)) != 1 {
		t.Fatal("durable tenant isolation", e)
	}
	audits := readTransportAudits(t, writer)
	domain, failures := 0, 0
	for _, a := range audits {
		if a.EventType != "admin_internal_ca_changed" {
			continue
		}
		domain++
		if stringPtrValue(a.ActorUserID) != "admin" || a.TenantID != "tenant_lab_001" || stringPtrValue(a.TargetType) != "internal_ca" {
			t.Fatalf("attribution %+v", a)
		}
		if stringPtrValue(a.Result) == "persistence_unconfirmed" {
			failures++
		}
	}
	if domain != 6 || failures != 2 {
		t.Fatal("domain audits", domain, failures)
	}
	raw, _ := json.Marshal(audits)
	for _, secret := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", "private-name", "private-ca-subject", "private-storage-location", "private-admin"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("audit leaked", secret)
		}
	}
	// A configured operator may see the fleet list; an unavailable store may not claim it is empty.
	operatorTenantAuthority.Store("tenant_lab_001")
	call("GET", "/admin/internal-cas/all", "", "admin", 200)
	unavailable := internalca.NewUnavailableStore("private-storage-location")
	h = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, InternalCAs: unavailable})
	call("GET", "/admin/internal-cas", "", "admin", 503)
	section := internalCABundleSection(unavailable)
	if section == nil || section.Complete {
		t.Fatal("unavailable store published complete empty list")
	}
	sourced := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, InternalCAs: s, ConfigSourceURL: "https://source.invalid"})
	h = sourced
	call("POST", "/admin/internal-cas", string(body), "admin", http.StatusConflict)
	call("DELETE", "/admin/internal-cas/foreign", "", "admin", http.StatusConflict)
}
func TestInternalCABundleRejectsWholeInvalidSectionAndReturnsRetryError(t *testing.T) {
	now := time.Now()
	s, _ := internalca.NewStore(nil)
	a := internalca.Authority{ID: "existing", TenantID: "tenant", CertificatePEM: anInternalAuthorityPEM(t, "Original")}
	s.Upsert(a, now)
	rev := s.ConfigGeneration()
	bad := a
	bad.ID = "bad"
	bad.CertificatePEM += "\nprivate-key-marker"
	for _, section := range []*internalCABundle{{Complete: true, Authorities: []internalca.Authority{bad}}, {Complete: true, Authorities: []internalca.Authority{a, a}}, {Complete: false}} {
		if _, ok, err := applyInternalCABundleSection(s, section, t.Logf); ok || err == nil {
			t.Fatal("bad section accepted")
		}
		if len(s.ListAll(now)) != 1 || s.ConfigGeneration() != rev {
			t.Fatal("bad section changed trust")
		}
	}
	if _, ok, err := applyInternalCABundleSection(nil, &internalCABundle{Complete: true}, nil); ok || err == nil {
		t.Fatal("missing store accepted")
	}
	if _, ok, err := applyInternalCABundleSection(s, &internalCABundle{Complete: true}, nil); !ok || err != nil || len(s.AnchorsPEM("tenant", now)) != 0 {
		t.Fatal("complete removal rejected")
	}
}

func TestInternalCASyncRetriesIncompleteSectionAtSameGeneration(t *testing.T) {
	s, _ := internalca.NewStore(nil)
	now := time.Now()
	s.Upsert(internalca.Authority{ID: "held", TenantID: "tenant", CertificatePEM: anInternalAuthorityPEM(t, "Held")}, now)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	type observation struct {
		failed     bool
		retained   int
		applied    bool
		generation uint64
	}
	observed := make(chan observation, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			failed := status.lastError != "" && !status.haveApplied
			status.mu.RUnlock()
			observed <- observation{failed: failed, retained: len(s.ListAll(now))}
		}
		if n == 4 {
			status.mu.RLock()
			o := observation{applied: status.haveApplied, generation: status.lastAppliedGeneration, retained: len(s.ListAll(now))}
			status.mu.RUnlock()
			observed <- o
			cancel()
		}
		json.NewEncoder(w).Encode(configBundlePayload{Generation: 23, Epoch: "internal-authority-retry", InternalCAs: &internalCABundle{Complete: n >= 3}})
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: "tenant_lab_001", url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), internalCAs: s})
	if polls.Load() < 4 || len(observed) != 2 {
		t.Fatal("no retry", polls.Load())
	}
	failed, ok := <-observed, <-observed
	if !failed.failed || failed.retained != 1 || !ok.applied || ok.generation != 23 || ok.retained != 0 {
		t.Fatalf("unexpected retry results: %+v %+v", failed, ok)
	}
}
