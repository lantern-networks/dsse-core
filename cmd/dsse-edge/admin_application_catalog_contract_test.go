package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminApplicationCatalogOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    ApplicationCatalogEntry:",
		"    ApplicationCatalogList:",
		"  /admin/applications:",
		"  /admin/applications/{application_id}:",
		"admin.applications.read",
		"admin.applications.write",
		`$ref: "#/components/schemas/ApplicationCatalogList"`,
		`$ref: "#/components/schemas/ApplicationCatalogEntry"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminApplicationCatalogAPIListsSeededRouteAndSaaSCatalog(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testApplicationCatalogEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			"app_catalog_private_001": {
				Protocol:               "tcp",
				ServiceFamily:          "ssh",
				DestinationRole:        "ssh_server",
				ApplicationSensitivity: "high",
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/applications?limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result appcatalog.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode application list: %v", err)
	}
	if result.Count != 2 || result.Limit != 10 || len(result.Applications) != 2 {
		t.Fatalf("application list = %#v, want seeded private and SaaS apps", result)
	}
	byID := map[string]appcatalog.Entry{}
	for _, app := range result.Applications {
		byID[app.ApplicationID] = app
	}
	privateApp := byID["app_catalog_private_001"]
	if privateApp.ApplicationType != "private_app" || privateApp.ServiceFamily != "ssh" || privateApp.RouteRef != "route_profile_configured" {
		t.Fatalf("private app = %#v, want sanitized seeded route catalog entry", privateApp)
	}
	saasApp := byID["saas_catalog_001"]
	if saasApp.ApplicationType != "saas" || saasApp.SaaSProvider != "catalog_provider" || saasApp.DomainPatternCount != 1 {
		t.Fatalf("saas app = %#v, want sanitized SaaS catalog entry", saasApp)
	}
}

func TestAdminApplicationCatalogAPIUpsertThenDetailRead(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"application_id":"app_catalog_custom_001",
		"tenant_id":"tenant_lab_001",
		"name":"Custom SSH App",
		"application_type":"private_app",
		"service_family":"ssh",
		"protocol":"tcp",
		"destination_role":"ssh_server",
		"application_sensitivity":"high",
		"route_ref":"route_ref_ssh_001",
		"status":"active",
		"tags":["admin","critical"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var created appcatalog.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created application: %v", err)
	}
	if created.ApplicationID != "app_catalog_custom_001" || created.TenantID != "tenant_lab_001" || created.RouteRef != "route_ref_ssh_001" || created.UpdatedAt == nil {
		t.Fatalf("created application = %#v, want normalized tenant application", created)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/applications/app_catalog_custom_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail appcatalog.Entry
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode application detail: %v", err)
	}
	if detail.ApplicationID != created.ApplicationID || detail.TenantID != created.TenantID {
		t.Fatalf("detail application = %#v, want created application id/tenant", detail)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_application_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want admin_application_upserted", outbox.insertedAudits)
	}
	if outbox.insertedAudits[0].SourceIP != nil || stringPtrValue(outbox.insertedAudits[0].ActorUserID) != "admin_lab_bypass" {
		t.Fatalf("application audit must retain the resolved lab principal without raw source IP: %#v", outbox.insertedAudits[0])
	}
}

func TestAdminApplicationCatalogAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"application_id":"app_other_001","tenant_id":"tenant_other_001","name":"Other","application_type":"private_app","service_family":"ssh","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminApplicationCatalogAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_application_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_application_reader_001",
		Email:     "application-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_application_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "application-reader-token",
		TokenHash:                 adminTokenHash("raw-application-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.applications.read"},
		CreatedByAdminPrincipalID: "admin_application_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(`{"application_id":"app_scope_denied_001","application_type":"private_app","service_family":"ssh"}`))
	req.Header.Set("authorization", "Bearer raw-application-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.applications.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}

func TestAdminApplicationCatalogAPIDelete(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			"app_seed_https": {ServiceFamily: "https"},
		},
	})

	// Author a custom application.
	body := `{"application_id":"app_delete_me_001","tenant_id":"tenant_lab_001","name":"Delete Me","application_type":"private_app","service_family":"https","status":"active"}`
	postReq := httptest.NewRequest(http.MethodPost, "/admin/applications", strings.NewReader(body))
	postReq.Header.Set("content-type", "application/json")
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("author status = %d, body=%s", postRec.Code, postRec.Body.String())
	}

	// Delete it: 200 + deleted:true.
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/applications/app_delete_me_001", nil)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK || !strings.Contains(delRec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete status = %d body=%s, want 200 deleted:true", delRec.Code, delRec.Body.String())
	}

	// It is gone from the list (only the seed remains).
	listReq := httptest.NewRequest(http.MethodGet, "/admin/applications?limit=100", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	var list appcatalog.ListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, app := range list.Applications {
		if app.ApplicationID == "app_delete_me_001" {
			t.Fatalf("deleted application still present in list: %#v", list.Applications)
		}
	}

	// Deleting again => 404 absent (idempotent at the resource level).
	delAgain := httptest.NewRecorder()
	handler.ServeHTTP(delAgain, httptest.NewRequest(http.MethodDelete, "/admin/applications/app_delete_me_001", nil))
	if delAgain.Code != http.StatusNotFound || !strings.Contains(delAgain.Body.String(), "absent") {
		t.Fatalf("re-delete status = %d body=%s, want 404 absent", delAgain.Code, delAgain.Body.String())
	}

	// A config-seed entry is NOT deletable => 404 with the config-seeded explanation.
	seedDel := httptest.NewRecorder()
	handler.ServeHTTP(seedDel, httptest.NewRequest(http.MethodDelete, "/admin/applications/app_seed_https", nil))
	if seedDel.Code != http.StatusNotFound || !strings.Contains(seedDel.Body.String(), "config-seeded") {
		t.Fatalf("seed delete status = %d body=%s, want 404 config-seeded", seedDel.Code, seedDel.Body.String())
	}

	// Exactly one delete audit, secret-safe.
	var deletes int
	for _, a := range outbox.insertedAudits {
		if a.EventType == "admin_application_deleted" {
			deletes++
			if a.TargetID == nil || *a.TargetID != "app_delete_me_001" {
				t.Fatalf("delete audit target = %v, want app_delete_me_001", a.TargetID)
			}
			if a.SourceIP != nil || stringPtrValue(a.ActorUserID) != "admin_lab_bypass" {
				t.Fatalf("delete audit must retain the resolved lab principal without raw source IP: %#v", a)
			}
		}
	}
	if deletes != 1 {
		t.Fatalf("delete audits = %d, want 1", deletes)
	}
}

// TestRouteProfilesDropPublishedAppOnDelete proves the route overlay reflects a delete: a published authored app
// contributes a route, and deleting it removes that route (fail-closed: the published app becomes unreachable
// without a separate unpublish).
func TestRouteProfilesDropPublishedAppOnDelete(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant_lab_001"
	now := time.Now().UTC()
	store := newAdminApplicationCatalogStore(tenantID, nil, nil)
	if err := store.SetStatePath(""); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	if _, err := store.Upsert(ctx, appcatalog.Entry{
		ApplicationID:   "app_pub_001",
		TenantID:        tenantID,
		ApplicationType: "private_app",
		Destination:     "jira.internal.example.com",
		DestinationPort: 443,
		PublishProtocol: "web",
		Published:       true,
		Status:          "active",
	}, tenantID, now); err != nil {
		t.Fatalf("publish upsert: %v", err)
	}

	merged := edgeplane.RouteProfilesWithPublishedCatalog(map[string]edgeplane.ApplicationRouteProfile{}, store, tenantID)
	if _, ok := merged["app_pub_001"]; !ok {
		t.Fatalf("published app missing from route overlay: %#v", merged)
	}

	if err := store.Delete(ctx, tenantID, "app_pub_001"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mergedAfter := edgeplane.RouteProfilesWithPublishedCatalog(map[string]edgeplane.ApplicationRouteProfile{}, store, tenantID)
	if _, ok := mergedAfter["app_pub_001"]; ok {
		t.Fatalf("deleted published app still in route overlay: %#v", mergedAfter)
	}
}

func testApplicationCatalogEvaluator() decision.Evaluator {
	evaluator := testEvaluator()
	evaluator.PolicyBundle.SaaSCatalog = []model.SaaSCatalogEntry{
		{
			TenantID:          "tenant_lab_001",
			SaaSApplicationID: "saas_catalog_001",
			Name:              "Catalog SaaS",
			Provider:          "catalog_provider",
			Category:          "collaboration",
			RiskTier:          "medium",
			DomainPatterns:    []string{"domain_pattern_ref_001"},
			Tags:              []string{"collaboration"},
		},
	}
	return evaluator
}
