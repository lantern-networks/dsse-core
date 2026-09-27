package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresDelegatedRevocationReportRecovery(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "revocation_report")
	gate := &delegatedPGGate{postgresBlobPersister: p}
	cp := delegatedgrant.NewStore(0)
	if err := cp.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	own := delegatedFixture("tenant_lab_001", "report-grant")
	for _, g := range []model.DelegatedAccessGrant{own, delegatedFixture("other", own.ID)} {
		if _, err := cp.Upsert(g); err != nil {
			t.Fatal(err)
		}
	}
	local := delegatedgrant.NewStore(0)
	path := filepath.Join(t.TempDir(), "grants.json")
	if err := local.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Upsert(own); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A missing machine-door reporter must not turn a local revocation into a fleet-wide success.
	edge := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, LabMode: boolPtr(true), ConfigSourceURL: "https://cp.invalid/config-bundle", DelegatedGrants: local, DelegatedGrantStorePath: path})
	req := httptest.NewRequest("POST", "/delegated-grants/"+own.ID+"/revoke", strings.NewReader(`{"revocation_reason":"requested"}`))
	rec := httptest.NewRecorder()
	edge.ServeHTTP(rec, req)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"local_revoked":true`) {
		t.Fatalf("unconfirmed revoke: %d %s", rec.Code, rec.Body)
	}
	restarted := delegatedgrant.NewStore(0)
	if err := restarted.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if g, _ := restarted.GetForTenant(own.TenantID, own.ID); g.Status != "revoked" {
		t.Fatal("local revocation lost on restart")
	}
	mux := http.NewServeMux()
	registerDelegatedRevocationReport(mux, cp, nil, "", true, writer)
	server := httptest.NewServer(mux)
	defer server.Close()
	reporter := &delegatedRevocationReporter{url: server.URL + "/delegated-grant-revocations", client: server.Client()}
	before := cp.ConfigGeneration()
	gate.fail = true
	g, _ := restarted.GetForTenant(own.TenantID, own.ID)
	if err := reporter.report(context.Background(), g); err == nil {
		t.Fatal("CP persistence failure acknowledged")
	}
	peer := delegatedgrant.NewStore(0)
	if err := peer.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if g, _ := peer.GetForTenant(own.TenantID, own.ID); g.Status != "active" {
		t.Fatal("failed transaction committed")
	}
	gate.fail = false
	reporter.reconcileOnce(context.Background(), restarted)
	if g, _ := peer.GetForTenant(own.TenantID, own.ID); g.Status != "revoked" {
		t.Fatal("revocation not persisted by authority")
	}
	after := cp.ConfigGeneration()
	if after <= before {
		t.Fatal("CP did not publish a new generation")
	}
	if err := reporter.report(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if cp.ConfigGeneration() != after {
		t.Fatal("idempotent retry advanced generation")
	}
	if g, _ := peer.GetForTenant("other", own.ID); g.Status != "active" {
		t.Fatal("other tenant revoked")
	}
	secondEdge := delegatedgrant.NewStore(0)
	src := configBundleSource{}
	if _, err := src.apply(configBundlePayload{DelegatedGrants: &delegatedGrantBundle{Grants: peer.Snapshot()}}, configApplyTargets{delegatedGrants: secondEdge}); err != nil {
		t.Fatal(err)
	}
	if g, _ := secondEdge.GetForTenant(own.TenantID, own.ID); delegatedgrant.IsActive(g, time.Now()) {
		t.Fatal("another Edge still permits revoked grant")
	}
	rows := readConnectorManagementAudits(t, writer)
	found := false
	for _, row := range rows {
		if row.EventType == "delegated_access_grant_revocation_reported" && row.TenantID == own.TenantID {
			found = true
		}
	}
	if !found {
		t.Fatal("CP revocation audit missing")
	}
}

func TestDelegatedRevocationReportAuthorization(t *testing.T) {
	old := auditIngestAuthorityMap
	defer func() { auditIngestAuthorityMap = old }()
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-test": {"own"}}}
	store := delegatedgrant.NewStore(0)
	for _, tenant := range []string{"own", "other"} {
		if _, err := store.Upsert(delegatedFixture(tenant, "g")); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerDelegatedRevocationReport(mux, store, nil, "", false, nil)
	for _, tc := range []struct {
		name, body string
		cert       bool
		want       int
	}{
		{"anonymous", `{"tenant_id":"own","grant_id":"g"}`, false, 403},
		{"foreign", `{"tenant_id":"other","grant_id":"g"}`, true, 403},
		{"missing", `{"tenant_id":"own","grant_id":"absent"}`, true, 404},
		{"trailing", `{"tenant_id":"own","grant_id":"g"}{}`, true, 400},
		{"allowed", `{"tenant_id":"own","grant_id":"g","reason":"requested"}`, true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/delegated-grant-revocations", strings.NewReader(tc.body))
			if tc.cert {
				req.TLS = reqWithClientCertCN("edge-test").TLS
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if g, _ := store.GetForTenant("other", "g"); g.Status != "active" {
		t.Fatal("unauthorized grant changed")
	}
	edge := http.NewServeMux()
	registerDelegatedRevocationReport(edge, store, nil, "https://cp.invalid", true, nil)
	w := httptest.NewRecorder()
	edge.ServeHTTP(w, httptest.NewRequest("POST", "/delegated-grant-revocations", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatal("Edge registered authority endpoint")
	}
}

func TestDelegatedRevocationReporterRequiresExactConfirmation(t *testing.T) {
	for _, body := range []string{`{}`, `{"tenant_id":"other","grant_id":"g","status":"revoked"}`, `{"tenant_id":"own","grant_id":"g","status":"active"}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		p := &delegatedRevocationReporter{url: s.URL, client: s.Client()}
		g := delegatedFixture("own", "g")
		g.Status = "revoked"
		if err := p.report(context.Background(), g); err == nil {
			t.Fatal("accepted unrelated acknowledgement")
		}
		s.Close()
	}
}
