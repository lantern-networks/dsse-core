package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestAccountAndBoundaryRejectedSaveHasNoSuccessAudit(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	accounts, policies := nhi.NewStore(), policy.NewStore(nil)
	ap := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "accounts.json")}}
	pp := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "policies.json")}}
	if err := accounts.SetPersister(ap); err != nil {
		t.Fatal(err)
	}
	if err := policies.SetRuntimeStatePersister(pp); err != nil {
		t.Fatal(err)
	}
	foreign := model.NonHumanIdentity{ID: "same", Name: "Foreign", NHIType: "service_account", OwnerUserID: "foreign-owner", Status: "active"}
	if _, err := accounts.Upsert(ctx, foreign, "tenant_other", now); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "account-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "account-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("account-audit-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "account-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, AdminAuditOutbox: outbox, NonHumanIdentities: accounts, PolicyStore: policies})
	for _, tc := range []struct {
		path, body, event string
		p                 *riskAuditPersister
	}{
		{"/admin/non-human-identities", `{"id":"same","name":"Own","nhi_type":"service_account","owner_user_id":"own-person","status":"suspended"}`, "non_human_identity_upserted", ap},
		{"/admin/policies", `{"id":"pol-agent-same","name":"Boundary","status":"active","priority":50,"conditions":{"actor_nhi_id":"same"},"action":{"decision":"allow"},"allowed_tool_ids":["read"]}`, "admin_policy_upserted", pp},
	} {
		for _, fail := range []bool{true, false} {
			tc.p.fail.Store(fail)
			oldAccounts, oldPolicies := accounts.ConfigGeneration(), policies.ConfigGeneration()
			oldDomain := len(outbox.insertedAudits)
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer account-audit-fixture")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := 200
			if fail {
				want = 500
			}
			if rec.Code != want || strings.Contains(rec.Body.String(), "private-runtime-location") {
				t.Fatalf("response %d: %s", rec.Code, rec.Body)
			}
			if fail {
				if len(outbox.insertedAudits) != oldDomain || accounts.ConfigGeneration() != oldAccounts || policies.ConfigGeneration() != oldPolicies {
					t.Fatal("rejected save published generation or success audit")
				}
			} else {
				if len(outbox.insertedAudits) != oldDomain+1 {
					t.Fatal("missing accepted audit")
				}
				row := outbox.insertedAudits[oldDomain]
				if row.EventType != tc.event || stringPtrValue(row.ActorUserID) != "account-admin" || row.TenantID != "tenant_lab_001" {
					t.Fatalf("audit attribution: %+v", row)
				}
				if tc.event == "admin_policy_upserted" && row.Metadata["allowed_tool_id_count"] != 1 {
					t.Fatalf("missing tool count: %+v", row)
				}
			}
		}
	}
	other, _ := accounts.List(ctx, "tenant_other")
	if len(other) != 1 || other[0].Name != "Foreign" {
		t.Fatal("own account overwrote foreign account")
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 6 {
		t.Fatalf("original audit count: %d", len(rows))
	}
	failures := 0
	for _, row := range rows {
		if row.EventType == "admin_config_change" && stringPtrValue(row.Result) == "error" {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("failed save audit count: %d", failures)
	}
}

func TestPostgresAccountUnavailableIsPersistenceError(t *testing.T) {
	closedDB, err := sql.Open("postgres", "host=127.0.0.1 port=1 sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	closedDB.Close()
	for _, db := range []*sql.DB{nil, closedDB} {
		var generation uint64
		store := postgresNonHumanIdentityStore{DB: db, gen: &generation}
		_, err := store.Upsert(context.Background(), model.NonHumanIdentity{ID: "account", Name: "Account", NHIType: "service_account", OwnerUserID: "person", Status: "active"}, "tenant_lab_001", time.Now())
		if !errors.Is(err, nhi.ErrPersistence) || generation != 0 {
			t.Fatalf("failed database save: %v generation=%d", err, generation)
		}
	}
}
