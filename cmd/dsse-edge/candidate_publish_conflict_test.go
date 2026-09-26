package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

func TestCandidatePrivatePublishDoesNotOverwriteExistingApplication(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	tenant := testEvaluator().PolicyBundle.TenantID
	candidates := policycandidate.NewStore()
	c, err := candidates.ObserveConnectorDiscovered(ctx, tenant, "new.example", 443, "web", "conn", "site", "ns", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	apps := appcatalog.NewStore()
	path := filepath.Join(t.TempDir(), "apps.json")
	if err = apps.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	original, err := apps.Upsert(ctx, appcatalog.Entry{ApplicationID: "existing", Name: "Existing", ApplicationType: "private_app", Destination: "original.example", DestinationPort: 443, PublishProtocol: "web", Published: true, Status: "active"}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: newAdminAuthStore(), ApplicationCatalogStore: apps, PolicyCandidateStore: candidates})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/policy-candidates/"+c.CandidateID+"/approve-private-app", strings.NewReader(`{"application_id":"existing"}`)))
	if w.Code != 409 {
		t.Fatalf("collision returned %d: %s", w.Code, w.Body)
	}
	fresh := appcatalog.NewStore()
	if err = fresh.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	got, found, err := fresh.Get(ctx, tenant, "existing")
	if err != nil || !found || !reflect.DeepEqual(got, original) {
		t.Fatal("existing application changed", got, err)
	}
	current, _, err := candidates.Get(ctx, tenant, c.CandidateID)
	if err != nil || current.Status != "pending" {
		t.Fatal("candidate approved despite conflict", current, err)
	}
}
