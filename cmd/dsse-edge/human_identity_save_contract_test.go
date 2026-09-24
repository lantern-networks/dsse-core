package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type humanIdentityFailSave struct {
	base blobstore.Persister
	fail bool
}

func (p *humanIdentityFailSave) Load() ([]byte, error) { return p.base.Load() }
func (p *humanIdentityFailSave) Save(data []byte) error {
	if p.fail {
		return errors.New("secret-directory-path")
	}
	return p.base.Save(data)
}

func TestAdminHumanIdentitySaveFailureAuditAndRetry(t *testing.T) {
	gate := &humanIdentityFailSave{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "people.json")}}
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if err := store.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(context.Background(), model.HumanIdentity{ID: "alice", Subject: "alice", Source: "manual"}, "tenant_lab_001", time.Now()); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	auth := seedAdminConnectorAPITokenAuth("people_writer", "people-write-token", []string{"admin.identity.read", "admin.identity.write"})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, AdminAuditOutbox: outbox, HumanIdentities: store})
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/human-identities", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer people-write-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	gate.fail = true
	generation := store.ConfigGeneration()
	for _, body := range []string{`{"id":"bob","subject":"bob","source":"manual","status":"active"}`, `{"id":"alice","subject":"alice","source":"manual","status":"deleted"}`} {
		rec := request(body)
		if rec.Code != 500 || !strings.Contains(rec.Body.String(), humanidentity.ErrDirectoryPersistence.Error()) || strings.Contains(rec.Body.String(), "secret-directory-path") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	users, _ := store.List(context.Background(), "tenant_lab_001")
	if len(users) != 1 || users[0].Status != "active" || store.ConfigGeneration() != generation {
		t.Fatalf("failed save applied: %#v", users)
	}
	for _, audit := range outbox.insertedAudits {
		if audit.EventType == "human_identity_upserted" {
			t.Fatal("rejected save produced success domain audit")
		}
	}
	failures := 0
	for _, audit := range outbox.wrapperAudits {
		if audit.EventType == "admin_config_change" {
			failures++
			if audit.Result == nil || *audit.Result != "error" {
				t.Fatalf("failed common audit: %#v", audit)
			}
		}
	}
	if failures != 2 {
		t.Fatalf("failed common audits=%d", failures)
	}
	gate.fail = false
	for _, body := range []string{`{"id":"bob","subject":"bob","source":"manual","status":"suspended"}`, `{"id":"alice","subject":"alice","source":"manual","status":"deleted"}`} {
		if rec := request(body); rec.Code != 200 {
			t.Fatalf("retry status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	count := 0
	for _, audit := range outbox.insertedAudits {
		if audit.EventType == "human_identity_upserted" {
			count++
			if audit.ActorUserID == nil || *audit.ActorUserID != "people_writer" || audit.TenantID != "tenant_lab_001" || (audit.Result == nil || *audit.Result != "success") {
				t.Fatalf("domain audit: %#v", audit)
			}
		}
	}
	if count != 2 {
		t.Fatalf("success domain count=%d", count)
	}
	again := humanidentity.NewHumanIdentityDirectoryStore()
	if err := again.SetPersister(gate.base); err != nil {
		t.Fatal(err)
	}
	users, _ = again.List(context.Background(), "tenant_lab_001")
	if len(users) != 2 || users[0].Status != "deleted" || users[1].Status != "suspended" {
		t.Fatalf("restart: %#v", users)
	}
}

func TestHumanIdentityMutationErrorMapsWrappedPersistence(t *testing.T) {
	rec := httptest.NewRecorder()
	writeHumanIdentityMutationError(rec, errors.Join(errors.New("import index"), humanidentity.ErrDirectoryPersistence))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "import index") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
