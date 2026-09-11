package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminHumanIdentityAuditOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    HumanIdentity:",
		"    HumanIdentityWrite:",
		"    HumanIdentityImportRequest:",
		"  /admin/human-identities:",
		"  /admin/human-identities/import:",
		"  /admin/human-identities/sources/policies:",
		"admin.identity.read",
		"admin.identity.write",
		"human_identity_metadata_recorded_scope=none",
		"human_identity_import_metadata_recorded_scope=none",
		"human_identity_source_policy_metadata_recorded_scope=none",
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminHumanIdentityAuditOmitsRawIdentityValues(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"id":"human_audit_001",
		"tenant_id":"tenant_lab_001",
		"subject":"raw-subject-human-audit",
		"email":"raw-human-audit@example.test",
		"display_name":"Raw Human Audit",
		"source":"scim",
		"department":"Raw Department",
		"status":"active",
		"metadata":{"raw_metadata_key":"raw metadata value"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	audit := insertedAuditByEventType(t, outbox, "human_identity_upserted")
	// ★ THE MINIMISATION HERE IS ABOUT THE DIRECTORY SUBJECT, NOT THE ADMINISTRATOR (2026-08-19, operator
	// decision). This used to assert ActorUserID must be nil, grouped with SourceIP as a "raw source/user
	// field" — and that grouping hid a real gap: a customer could see their people directory had been edited
	// and had to correlate by timestamp to learn by whom, while the envelope promises every operator act is
	// attributable. The subject's own values stay reduced to *_present booleans, which is what the assertions
	// below hold; the acting administrator is a different person and is now named.
	if audit.SourceIP != nil {
		t.Fatalf("human identity audit included the source IP: %#v", audit)
	}
	if audit.ActorUserID == nil || strings.TrimSpace(*audit.ActorUserID) == "" {
		t.Fatalf("human identity audit does not say who made the change: %#v", audit)
	}
	if audit.Metadata["human_identity_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_hot_reload"] != false {
		t.Fatalf("human identity audit metadata = %#v, want non-secret boundary", audit.Metadata)
	}
	assertAuditMetadataDoesNotContain(t, audit.Metadata, []string{
		"raw-subject-human-audit",
		"raw-human-audit@example.test",
		"Raw Human Audit",
		"Raw Department",
		"raw metadata value",
	})
}

func TestAdminHumanIdentitySourcePolicyAuditOmitsRawMetadata(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"source":"scim_audit",
		"connector_type":"scim",
		"enabled":true,
		"reconcile_missing":true,
		"expected_interval_seconds":3600,
		"stale_after_seconds":7200,
		"metadata":{"connector_id":"raw-connector-id"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities/sources/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	audit := insertedAuditByEventType(t, outbox, "human_identity_source_policy_upserted")
	// The minimisation here is about the record's SUBJECT, not the acting administrator (2026-08-19,
	// operator decision). The source IP stays out; who performed the act is now recorded, so a customer
	// reading this row does not have to correlate by timestamp against a separate admin_config_change row.
	if audit.SourceIP != nil {
		t.Fatalf("human identity source policy audit included the source IP: %#v", audit)
	}
	if audit.ActorUserID == nil || strings.TrimSpace(*audit.ActorUserID) == "" {
		t.Fatalf("human identity source policy audit does not say who made the change: %#v", audit)
	}
	if audit.Metadata["human_identity_source_policy_metadata_recorded_scope"] != "none" || audit.Metadata["metadata_key_count"] != float64(1) && audit.Metadata["metadata_key_count"] != 1 {
		t.Fatalf("source policy audit metadata = %#v, want non-secret metadata boundary", audit.Metadata)
	}
	assertAuditMetadataDoesNotContain(t, audit.Metadata, []string{"raw-connector-id"})
}

func TestAdminHumanIdentityImportAuditOmitsRawCheckpointAndIdentityValues(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"source":"scim_import_audit",
		"import_run_id":"human_import_audit_001",
		"checkpoint":"raw-checkpoint-value",
		"dry_run":true,
		"reconcile_missing":true,
		"identities":[
			{"id":"human_import_audit_001","subject":"raw-import-subject","email":"raw-import@example.test","display_name":"Raw Import User","status":"active"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	audit := insertedAuditByEventType(t, outbox, "human_identities_imported")
	// The minimisation here is about the record's SUBJECT, not the acting administrator (2026-08-19,
	// operator decision). The source IP stays out; who performed the act is now recorded, so a customer
	// reading this row does not have to correlate by timestamp against a separate admin_config_change row.
	if audit.SourceIP != nil {
		t.Fatalf("human identity import audit included the source IP: %#v", audit)
	}
	if audit.ActorUserID == nil || strings.TrimSpace(*audit.ActorUserID) == "" {
		t.Fatalf("human identity import audit does not say who started the import: %#v", audit)
	}
	if audit.Metadata["human_identity_import_metadata_recorded_scope"] != "none" || audit.Metadata["checkpoint_present"] != true {
		t.Fatalf("import audit metadata = %#v, want non-secret import boundary", audit.Metadata)
	}
	assertAuditMetadataDoesNotContain(t, audit.Metadata, []string{
		"raw-checkpoint-value",
		"raw-import-subject",
		"raw-import@example.test",
		"Raw Import User",
	})
}

func TestAdminHumanIdentityAuditRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := seedAdminConnectorAPITokenAuth("admin_human_identity_reader_001", "raw-human-identity-reader-token", []string{"admin.identity.read"})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: adminAuth,
	})
	body := `{"id":"human_scope_denied_001","tenant_id":"tenant_lab_001","subject":"scope-denied","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities", strings.NewReader(body))
	req.Header.Set("authorization", "Bearer raw-human-identity-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.identity.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}

func insertedAuditByEventType(t *testing.T, outbox *recordingAdminAuditOutboxDeadReader, eventType string) model.AuditLog {
	t.Helper()
	for _, audit := range outbox.insertedAudits {
		if audit.EventType == eventType {
			return audit
		}
	}
	t.Fatalf("audit event %s not found in %#v", eventType, outbox.insertedAudits)
	return model.AuditLog{}
}

func assertAuditMetadataDoesNotContain(t *testing.T, metadata map[string]any, forbidden []string) {
	t.Helper()
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal audit metadata: %v", err)
	}
	for _, leaked := range forbidden {
		if strings.Contains(string(encodedMetadata), leaked) {
			t.Fatalf("audit metadata leaked %q: %s", leaked, string(encodedMetadata))
		}
	}
}
