package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminNHIRegistryOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    NonHumanIdentity:",
		"    NonHumanIdentityList:",
		"  /admin/non-human-identities:",
		"admin.nhi.read",
		"admin.nhi.write",
		"nhi_metadata_recorded_scope=none",
		`$ref: "#/components/schemas/NonHumanIdentityList"`,
		`$ref: "#/components/schemas/NonHumanIdentity"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminNHIRegistryAPIUpsertAuditsNonSecretMetadata(t *testing.T) {
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
		"id":"nhi_admin_audit_001",
		"tenant_id":"tenant_lab_001",
		"name":"Raw NHI Name",
		"nhi_type":"ai_agent",
		"owner_user_id":"raw-owner-user-001",
		"trust_domain":"raw-trust-domain",
		"issuer":"raw-issuer",
		"subject":"raw-subject",
		"credential_type":"workload_jwt",
		"allowed_application_ids":["raw-app-001"],
		"allowed_scopes":["raw-scope-001"],
		"allowlist_enforced":true,
		"status":"active",
		"metadata":{"raw_metadata_key":"raw metadata value"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var created model.NonHumanIdentity
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created NHI: %v", err)
	}
	if created.ID != "nhi_admin_audit_001" || created.TenantID != "tenant_lab_001" || created.Status != "active" {
		t.Fatalf("created NHI = %#v, want tenant NHI", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/non-human-identities", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list nhi.ListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode NHI list: %v", err)
	}
	if list.Count != 1 || len(list.Identities) != 1 || list.Identities[0].ID != created.ID {
		t.Fatalf("NHI list = %#v, want created tenant NHI", list)
	}

	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "non_human_identity_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want NHI upsert", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	// The minimisation here is about the record's SUBJECT, not the acting administrator (2026-08-19,
	// operator decision). The source IP stays out; who performed the act is now recorded, so a customer
	// reading this row does not have to correlate by timestamp against a separate admin_config_change row.
	if audit.SourceIP != nil {
		t.Fatalf("NHI audit included the source IP: %#v", audit)
	}
	if audit.ActorUserID == nil || strings.TrimSpace(*audit.ActorUserID) == "" {
		t.Fatalf("NHI audit does not say which administrator registered it: %#v", audit)
	}
	if audit.Metadata["nhi_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_hot_reload"] != false {
		t.Fatalf("NHI audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
	}
	encodedMetadata, err := json.Marshal(audit.Metadata)
	if err != nil {
		t.Fatalf("marshal audit metadata: %v", err)
	}
	for _, leaked := range []string{
		"Raw NHI Name",
		"raw-owner-user-001",
		"raw-trust-domain",
		"raw-issuer",
		"raw-subject",
		"raw-app-001",
		"raw-scope-001",
		"raw metadata value",
	} {
		if strings.Contains(string(encodedMetadata), leaked) {
			t.Fatalf("NHI audit metadata leaked %q: %s", leaked, string(encodedMetadata))
		}
	}
}

func TestAdminNHIRegistryAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"id":"nhi_other_001","tenant_id":"tenant_other_001","name":"Other","nhi_type":"ai_agent","owner_user_id":"owner_other","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminNHIRegistryAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := seedAdminConnectorAPITokenAuth("admin_nhi_reader_001", "raw-nhi-reader-token", []string{"admin.nhi.read"})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: adminAuth,
	})
	body := `{"id":"nhi_scope_denied_001","tenant_id":"tenant_lab_001","name":"Scope Denied","nhi_type":"ai_agent","owner_user_id":"owner_scope","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", strings.NewReader(body))
	req.Header.Set("authorization", "Bearer raw-nhi-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.nhi.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}
