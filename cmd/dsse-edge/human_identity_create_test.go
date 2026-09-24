package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAdminHumanIdentityCreateRejectsExistingWithoutChangingUpsert(t *testing.T) {
	store := humanidentity.NewHumanIdentityDirectoryStore()
	original, err := store.Upsert(context.Background(), model.HumanIdentity{ID: "alice", Subject: "synced-alice", Source: "idp", Status: "suspended", Metadata: map[string]any{"keep": "yes"}}, "tenant_lab_001", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := seedAdminConnectorAPITokenAuth("people_writer", "people-write-token", []string{"admin.identity.read", "admin.identity.write"})
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, HumanIdentities: store, Writer: writer, AdminAuditOutbox: outbox})
	request := func(path, body string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer people-write-token")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	generation := store.ConfigGeneration()
	if got := request("/admin/human-identities?mode=create", `{"id":"alice","subject":"replacement","source":"manual","status":"active"}`); got != 409 {
		t.Fatalf("duplicate create status=%d", got)
	}
	users, _ := store.List(context.Background(), "tenant_lab_001")
	if !reflect.DeepEqual(users, []model.HumanIdentity{original}) || store.ConfigGeneration() != generation {
		t.Fatal("duplicate changed identity or generation")
	}
	if len(outbox.insertedAudits) != 0 {
		t.Fatal("duplicate produced success domain audit")
	}
	if got := request("/admin/human-identities?mode=create", `{"id":"bob","subject":"bob","source":"manual"}`); got != 200 {
		t.Fatalf("create=%d", got)
	}
	if got := request("/admin/human-identities", `{"id":"alice","subject":"updated-by-sync","source":"idp","status":"deleted"}`); got != 200 {
		t.Fatalf("upsert=%d", got)
	}
	if got := request("/admin/human-identities?mode=typo", `{"id":"oops","subject":"oops"}`); got != 400 {
		t.Fatalf("invalid mode=%d", got)
	}
	users, _ = store.List(context.Background(), "tenant_lab_001")
	if len(users) != 2 || users[0].Subject != "updated-by-sync" || users[0].Status != "deleted" {
		t.Fatalf("legacy upsert failed: %#v", users)
	}
	if len(outbox.insertedAudits) != 2 {
		t.Fatalf("success domain audits=%d", len(outbox.insertedAudits))
	}
}

// Wrapping only the runtime interface simulates an older backend without Create.
func TestAdminHumanIdentityCreateNeverFallsBackToUpsert(t *testing.T) {
	store := humanidentity.NewHumanIdentityDirectoryStore()
	legacy := struct {
		humanidentity.HumanIdentityDirectoryRuntimeStore
	}{store}
	auth := seedAdminConnectorAPITokenAuth("people_writer", "people-write-token", []string{"admin.identity.write"})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, HumanIdentities: legacy})
	req := httptest.NewRequest("POST", "/admin/human-identities?mode=create", strings.NewReader(`{"id":"alice","subject":"alice"}`))
	req.Header.Set("Authorization", "Bearer people-write-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	users, _ := store.List(context.Background(), "tenant_lab_001")
	if rec.Code != 503 || len(users) != 0 {
		t.Fatalf("status=%d users=%d", rec.Code, len(users))
	}
}
