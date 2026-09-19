package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestDelegationRuntimeLookupAndRevokeStayInTenant(t *testing.T) {
	store := delegatedgrant.NewStore(0)
	for _, grant := range []model.DelegatedAccessGrant{
		{ID: "shared", TenantID: "tenant_lab_001", ActorNHIID: "own-agent", SubjectUserID: "own-person", Status: "active"},
		{ID: "shared", TenantID: "tenant_other", ActorNHIID: "foreign-agent", SubjectUserID: "foreign-person", Status: "active"},
		{ID: "foreign-only", TenantID: "tenant_other", ActorNHIID: "foreign-agent", SubjectUserID: "foreign-person", Status: "active"},
	} {
		if _, err := store.Upsert(grant); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, DelegatedGrants: store})
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/delegated-grants/shared", 200},
		{http.MethodGet, "/delegated-grants/foreign-only", 404},
		{http.MethodPost, "/delegated-grants/foreign-only/revoke", 404},
		{http.MethodPost, "/delegated-grants/shared/revoke", 200},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body.String())
		}
		if tc.status == 200 {
			var grant model.DelegatedAccessGrant
			if err := json.Unmarshal(rec.Body.Bytes(), &grant); err != nil || grant.TenantID != "tenant_lab_001" || grant.ActorNHIID != "own-agent" {
				t.Fatalf("wrong tenant: %+v %v", grant, err)
			}
		}
	}
	for _, id := range []string{"shared", "foreign-only"} {
		grant, ok := store.GetForTenant("tenant_other", id)
		if !ok || grant.Status != "active" {
			t.Fatalf("foreign grant changed: %+v", grant)
		}
	}
	grant, _ := store.GetForTenant("tenant_lab_001", "shared")
	if grant.Status != "revoked" {
		t.Fatal("own revocation was not applied")
	}
}

func TestDelegationSaveFailureAuditAndTenantBoundary(t *testing.T) {
	for _, replaceBeforeError := range []bool{false, true} {
		name := "refused"
		if replaceBeforeError {
			name = "replaced_unconfirmed"
		}
		t.Run(name, func(t *testing.T) { checkDelegationSaveFailureAuditAndTenantBoundary(t, replaceBeforeError) })
	}
}

func checkDelegationSaveFailureAuditAndTenantBoundary(t *testing.T, replaceBeforeError bool) {
	now := time.Now()
	store := delegatedgrant.NewStore(0)
	p := &revocationAuditPersister{replaceBeforeError: replaceBeforeError, base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if e := store.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e := store.Upsert(model.DelegatedAccessGrant{ID: "shared", TenantID: "tenant_other", ActorNHIID: "foreign-agent", SubjectUserID: "foreign-person", Status: "active"}); e != nil {
		t.Fatal(e)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "grant-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "grant-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("grant-audit-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "grant-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, AdminAuditOutbox: outbox, DelegatedGrants: store})
	if e := store.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer grant-audit-fixture")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	body := `{"id":"shared","actor_nhi_id":"own-agent","subject_user_id":"own-person","tool_ids":["read"],"status":"active"}`
	for _, tc := range []struct {
		path, body string
		fail       bool
	}{{"/admin/delegated-grants", body, true}, {"/admin/delegated-grants", body, false}, {"/admin/delegated-grants/shared/revoke", `{}`, true}, {"/admin/delegated-grants/shared/revoke", `{}`, false}} {
		p.fail.Store(tc.fail)
		gen := store.ConfigGeneration()
		domain := len(outbox.insertedAudits)
		before, _ := p.Load()
		r := post(tc.path, tc.body)
		want := 200
		if tc.fail {
			want = 500
		}
		if r.Code != want || strings.Contains(r.Body.String(), "private-runtime-location") {
			t.Fatalf("response %d: %s", r.Code, r.Body)
		}
		if tc.fail {
			after, _ := p.Load()
			if store.ConfigGeneration() != gen || len(outbox.insertedAudits) != domain || (!replaceBeforeError && string(before) != string(after)) {
				t.Fatal("rejected mutation changed state/generation/audit")
			}
		} else {
			if store.ConfigGeneration() != gen+1 || len(outbox.insertedAudits) != domain+1 {
				t.Fatal("accepted mutation missing generation or audit")
			}
			a := outbox.insertedAudits[domain]
			if stringPtrValue(a.ActorUserID) != "grant-admin" || a.TenantID != "tenant_lab_001" || stringPtrValue(a.TargetID) != "shared" {
				t.Fatalf("audit attribution %+v", a)
			}
		}
	}
	other, ok := store.GetForTenant("tenant_other", "shared")
	if !ok || other.Status != "active" || other.ActorNHIID != "foreign-agent" {
		t.Fatal("own operation changed foreign grant")
	}
	// Both the actor derivation and tool-reference validation use the requested tenant.
	own := deriveDecisionRequestActor(model.DecisionRequest{TenantID: "tenant_lab_001", DelegatedAccessGrantID: "shared"}, store)
	foreign := deriveDecisionRequestActor(model.DecisionRequest{TenantID: "tenant_other", DelegatedAccessGrantID: "shared"}, store)
	if own.ActorNHIID != "own-agent" || foreign.ActorNHIID != "foreign-agent" {
		t.Fatal("actor derivation crossed tenant")
	}
	foreignGrant := "only-foreign"
	store.Upsert(model.DelegatedAccessGrant{ID: foreignGrant, TenantID: "tenant_other", ActorNHIID: "own-agent", SubjectUserID: "foreign-person", Status: "active"})
	if err := validateToolCallEventReferences(model.ToolCallEvent{TenantID: "tenant_lab_001", ActorNHIID: "own-agent", ToolID: "read", DelegatedAccessGrantID: &foreignGrant}, "tenant_lab_001", nil, nil, store, nil, now); err == nil {
		t.Fatal("tool event accepted another tenant's grant")
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 6 {
		t.Fatalf("audit count %d", len(rows))
	}
	failures := 0
	for _, r := range rows {
		if r.EventType == "admin_config_change" && stringPtrValue(r.Result) == "error" {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("failure audit count %d", failures)
	}
}
func TestDelegationRevocationDistributesForOnlyItsTenant(t *testing.T) {
	cp, edge := delegatedgrant.NewStore(0), delegatedgrant.NewStore(0)
	for _, tenant := range []string{"tenant_a", "tenant_b"} {
		cp.Upsert(model.DelegatedAccessGrant{ID: "shared", TenantID: tenant, ActorNHIID: "agent", SubjectUserID: "person", Status: "active"})
	}
	src := configBundleSource{tenantID: "tenant_a"}
	targets := configApplyTargets{policyStore: policy.NewStore(nil), delegatedGrants: edge}
	if _, err := src.apply(configBundlePayload{DelegatedGrants: &delegatedGrantBundle{Grants: cp.Snapshot()}}, targets); err != nil {
		t.Fatal(err)
	}
	gen := cp.ConfigGeneration()
	if _, err := cp.RevokeForTenant("tenant_a", "shared", "review", time.Now()); err != nil {
		t.Fatal(err)
	}
	if cp.ConfigGeneration() != gen+1 {
		t.Fatal("revocation not distributed as a generation change")
	}
	if _, err := src.apply(configBundlePayload{DelegatedGrants: &delegatedGrantBundle{Grants: cp.Snapshot()}}, targets); err != nil {
		t.Fatal(err)
	}
	a, _ := edge.GetForTenant("tenant_a", "shared")
	b, _ := edge.GetForTenant("tenant_b", "shared")
	if a.Status != "revoked" || b.Status != "active" {
		t.Fatalf("bundle tenant state: %+v %+v", a, b)
	}
	if _, _, err := adminGetDelegatedAccessGrant(edge, context.Background(), "tenant_a", "shared"); err != nil {
		t.Fatal(err)
	}
}
