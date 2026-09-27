package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

const transportAuditBearer = "test-transport-audit-private-bearer"
const transportAuditReadBearer = "test-transport-audit-read-private-bearer"
const transportAuditOperatorBearer = "test-transport-audit-operator-private-bearer"

func transportAuditHandler(t *testing.T) (http.Handler, *logs.Writer, *revocation.AdmissionRevocations, *recordingAdminAuditOutboxDeadReader) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	now := time.Now().UTC()
	for id, tenant := range map[string]string{"owned-device": "tenant_lab_001", "other-device": "tenant_other"} {
		if _, err := ledger.Enroll(id, tenant, "", now.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "transport-admin", TenantID: "tenant_lab_001", Subject: "transport-admin", Email: "transport-admin@example.test",
		Roles: []string{"admin"}, IDPID: "test_idp", Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	for raw, scopes := range map[string][]string{transportAuditBearer: {"*"}, transportAuditReadBearer: {"admin.endpoints.read"}} {
		auth.UpsertAPIToken(adminAPIToken{
			ID: "token-" + scopes[0], TenantID: "tenant_lab_001", Name: "transport audit fixture", TokenHash: adminTokenHash(raw),
			Roles: []string{"admin"}, Scopes: scopes, CreatedByAdminPrincipalID: "transport-admin",
			CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
		})
	}
	auth.UpsertPrincipal(adminPrincipal{
		ID: "transport-operator", TenantID: "tenant_lab_001", Subject: "transport-operator", Email: "operator@example.test",
		Roles: []string{"admin", "super_admin"}, IDPID: "test_idp", Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "token-operator", TenantID: "tenant_lab_001", Name: "operator audit fixture", TokenHash: adminTokenHash(transportAuditOperatorBearer),
		Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "transport-operator",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	overlay := revocation.NewAdmissionRevocations()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth,
		EnrolledLedger: ledger, AdmissionRevocations: overlay, AdminAuditOutbox: outbox,
		OperatorTenantID: "tenant_lab_001",
	})
	return handler, writer, overlay, outbox
}

func transportAuditRequest(handler http.Handler, action, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/transport-admission/"+action, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func readTransportAudits(t *testing.T, writer *logs.Writer) []model.AuditLog {
	t.Helper()
	f, err := os.Open(filepath.Join(writer.Dir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []model.AuditLog
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var row model.AuditLog
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
		for _, forbidden := range []string{transportAuditBearer, transportAuditReadBearer, transportAuditOperatorBearer, "private-extra-request-value"} {
			if bytes.Contains(scanner.Bytes(), []byte(forbidden)) {
				t.Fatalf("audit included request material %q", forbidden)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAdminTransportAdmissionAuditNamesTargetAndActor(t *testing.T) {
	handler, writer, overlay, outbox := transportAuditHandler(t)
	for _, action := range []string{"revoke", "restore"} {
		body := `{"identity":" OWNED-DEVICE ","reason":"  incident-42  ","extra":"private-extra-request-value"}`
		if rec := transportAuditRequest(handler, action, body, transportAuditBearer); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", action, rec.Code, rec.Body.String())
		}
		_, revoked := overlay.IsRevoked("owned-device")
		if revoked != (action == "revoke") {
			t.Fatalf("%s overlay revoked=%v", action, revoked)
		}
	}
	var domain, common []model.AuditLog
	for _, row := range readTransportAudits(t, writer) {
		switch row.EventType {
		case "transport_admission_changed":
			domain = append(domain, row)
		case "admin_config_change":
			common = append(common, row)
		}
	}
	if len(domain) != 2 || len(common) != 2 {
		t.Fatalf("domain audits=%d, common audits=%d; want both transport actions attributable to their device", len(domain), len(common))
	}
	for i, action := range []string{"revoke", "restore"} {
		row := domain[i]
		if row.TenantID != "tenant_lab_001" || stringPtrValue(row.ActorUserID) != "transport-admin" ||
			stringPtrValue(row.TargetType) != "device" || stringPtrValue(row.TargetID) != "owned-device" ||
			stringPtrValue(row.Action) != "transport_admission_"+action || stringPtrValue(row.Result) != "success" ||
			row.Metadata["identity"] != "owned-device" || row.Metadata["action"] != action {
			t.Fatalf("%s identity/action metadata incomplete: %+v", action, row)
		}
		if _, err := time.Parse(time.RFC3339, row.Timestamp); err != nil {
			t.Fatalf("invalid audit timestamp: %v", err)
		}
		if action == "revoke" {
			if row.Metadata["reason"] != "incident-42" || stringPtrValue(row.Reason) != "incident-42" {
				t.Fatalf("revocation reason missing: %+v", row)
			}
		} else if _, ok := row.Metadata["reason"]; ok || row.Reason != nil {
			t.Fatalf("restore recorded a reason its operation did not accept: %+v", row)
		}
	}
	if len(outbox.insertedAudits) != 2 || len(outbox.wrapperAudits) != 2 {
		t.Fatalf("audit outbox has domain=%d, common=%d records; want two of each", len(outbox.insertedAudits), len(outbox.wrapperAudits))
	}
}

func TestAdminTransportAdmissionOperatorAuditBelongsToAffectedTenant(t *testing.T) {
	handler, writer, _, _ := transportAuditHandler(t)
	for _, action := range []string{"revoke", "restore"} {
		if rec := transportAuditRequest(handler, action, `{"identity":"other-device"}`, transportAuditOperatorBearer); rec.Code != http.StatusOK {
			t.Fatalf("operator %s: %d %s", action, rec.Code, rec.Body.String())
		}
	}
	count := 0
	for _, row := range readTransportAudits(t, writer) {
		if row.EventType != "transport_admission_changed" {
			continue
		}
		count++
		if row.TenantID != "tenant_other" || stringPtrValue(row.TargetID) != "other-device" ||
			stringPtrValue(row.ActorUserID) != "transport-operator" || row.Metadata["operator_tenant_id"] != "tenant_lab_001" ||
			row.Metadata["operator_principal_id"] != "transport-operator" {
			t.Fatalf("operator audit lost affected tenant or actor provenance: %+v", row)
		}
	}
	if count != 2 {
		t.Fatalf("operator domain audits=%d, want two", count)
	}
}

func TestAdminTransportAdmissionRefusalsHaveNoSuccessDomainAudit(t *testing.T) {
	handler, writer, overlay, _ := transportAuditHandler(t)
	overlay.Revoke("other-device", "other tenant incident")
	for _, action := range []string{"revoke", "restore"} {
		for _, tc := range []struct {
			name, body, bearer string
			status             int
		}{
			{"other tenant", `{"identity":"other-device"}`, transportAuditBearer, http.StatusNotFound},
			{"insufficient permission", `{"identity":"owned-device"}`, transportAuditReadBearer, http.StatusForbidden},
			{"missing identity", `{}`, transportAuditBearer, http.StatusBadRequest},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				if rec := transportAuditRequest(handler, action, tc.body, tc.bearer); rec.Code != tc.status {
					t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
				}
			})
		}
	}
	if _, revoked := overlay.IsRevoked("owned-device"); revoked {
		t.Fatal("refused request modified the owned device")
	}
	if reason, revoked := overlay.IsRevoked("other-device"); !revoked || reason != "other tenant incident" {
		t.Fatal("refused request modified another tenant's revocation")
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 6 {
		t.Fatalf("refusal audit rows=%d, want six refused requests", len(rows))
	}
	for _, row := range rows {
		if row.EventType == "transport_admission_changed" || stringPtrValue(row.Result) == "success" {
			t.Fatalf("refused request emitted a successful domain audit: %+v", row)
		}
	}
}

func TestAdminTransportAdmissionAuditWriterFailureIsObservable(t *testing.T) {
	handler, writer, overlay, outbox := transportAuditHandler(t)
	if err := os.Mkdir(filepath.Join(writer.Dir(), "audit.log.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	if rec := transportAuditRequest(handler, "revoke", `{"identity":"owned-device"}`, transportAuditBearer); rec.Code != http.StatusOK {
		t.Fatalf("audit store failure changed operation behavior: %d %s", rec.Code, rec.Body.String())
	}
	if _, revoked := overlay.IsRevoked("owned-device"); !revoked {
		t.Fatal("revocation was not applied")
	}
	if !strings.Contains(output.String(), `admin_audit_write_failed event="transport_admission_changed"`) {
		t.Fatalf("domain audit failure was silent: %s", output.String())
	}
	if len(outbox.insertedAudits) != 0 || len(outbox.wrapperAudits) != 0 {
		t.Fatal("failed primary audit was unexpectedly mirrored as if written")
	}
}
