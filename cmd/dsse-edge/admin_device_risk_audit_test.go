package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type riskAuditPersister struct {
	base blobstore.FilePersister
	fail atomic.Bool
}

func (p *riskAuditPersister) Load() ([]byte, error) { return p.base.Load() }
func (p *riskAuditPersister) Save(b []byte) error {
	if p.fail.Load() {
		return errors.New("private-runtime-location failure")
	}
	return p.base.Save(b)
}
func deviceRiskAuditHandler(t *testing.T) (http.Handler, *logs.Writer, *revocation.HighRiskOverlay, *recordingAdminAuditOutboxDeadReader, *device.Store, *riskAuditPersister) {
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
	overlay := revocation.NewHighRiskOverlay()
	overlay.SetStatePath(filepath.Join(t.TempDir(), "risk.json"))
	runtime := device.NewStore()
	persister := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "runtime.json")}}
	if err := runtime.SetPersister(persister); err != nil {
		t.Fatal(err)
	}
	for id, tenant := range map[string]string{"owned-device": "tenant_lab_001", "other-device": "tenant_other"} {
		bundle := testEvaluator().PolicyBundle
		bundle.TenantID = tenant
		if _, err := runtime.Register(model.Device{ID: id, TenantID: tenant}, bundle, now); err != nil {
			t.Fatal(err)
		}
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth,
		EnrolledLedger: ledger, HighRiskOverlay: overlay, DeviceStore: runtime, AdminAuditOutbox: outbox,
		OperatorTenantID: "tenant_lab_001",
	})
	return handler, writer, overlay, outbox, runtime, persister
}

func deviceRiskRequest(handler http.Handler, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/risk-signals", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
func TestDeviceRiskAuditTracksAcceptedSeverityAndRuntimeSaveWarning(t *testing.T) {
	handler, writer, overlay, outbox, runtime, persister := deviceRiskAuditHandler(t)
	for _, tc := range []struct {
		severity string
		fail     bool
	}{
		{"none", false}, {"medium", false}, {"high", false}, {"critical", false}, {"none", false},
		{"high", true}, {"high", false}, {"none", true}, {"none", false},
	} {
		before, err := persister.Load()
		if err != nil {
			t.Fatal(err)
		}
		persister.fail.Store(tc.fail)
		body := `{"entity_type":"device","entity_id":"owned-device","severity":"` + tc.severity + `","evidence_ref":"private-extra-request-value","extra":"private-extra-request-value"}`
		rec := deviceRiskRequest(handler, body, transportAuditBearer)
		if rec.Code != 200 {
			t.Fatalf("risk %s: %d %s", tc.severity, rec.Code, rec.Body)
		}
		var response adminRiskSignalResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if !response.Applied || response.Severity != tc.severity || (response.NotStoredDurably != "") != tc.fail {
			t.Fatalf("incorrect result: %+v", response)
		}
		if strings.Contains(rec.Body.String(), "private-runtime-location") || strings.Contains(rec.Body.String(), "will be gone") {
			t.Fatalf("unsafe or overconfident warning: %s", rec.Body)
		}
		dev, _ := runtime.Get("owned-device")
		if dev.Metadata["risk_state_severity"] != tc.severity {
			t.Fatal("live risk not applied")
		}
		wantOverlay := tc.severity
		if wantOverlay == "none" {
			wantOverlay = ""
		}
		if overlay.Snapshot()["owned-device"] != wantOverlay {
			t.Fatal("overlay did not follow live risk")
		}
		after, err := persister.Load()
		if err != nil {
			t.Fatal(err)
		}
		if tc.fail && !bytes.Equal(before, after) {
			t.Fatal("failing runtime save replaced file")
		}
		reloaded := device.NewStore()
		if err := reloaded.SetPersister(persister.base); err != nil {
			t.Fatal(err)
		}
		saved, _ := reloaded.Get("owned-device")
		if !tc.fail && saved.Metadata["risk_state_severity"] != tc.severity {
			t.Fatal("normal save not durable")
		}
		var last *model.AuditLog
		for _, row := range readTransportAudits(t, writer) {
			if row.EventType == "device_risk_changed" {
				copy := row
				last = &copy
			}
		}
		if last == nil {
			t.Fatal("missing target-specific device risk audit")
		}
		result := "success"
		if tc.fail {
			result = "partial"
		}
		if stringPtrValue(last.TargetID) != "owned-device" || stringPtrValue(last.ActorUserID) != "transport-admin" || last.TenantID != "tenant_lab_001" || stringPtrValue(last.Result) != result || last.Metadata["severity"] != tc.severity || last.Metadata["runtime_persistence_warning"] != tc.fail || last.Metadata["applied"] != true {
			t.Fatalf("incomplete audit: %+v", last)
		}
		if _, err := time.Parse(time.RFC3339, last.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	if len(outbox.insertedAudits) != 9 || len(outbox.wrapperAudits) != 9 {
		t.Fatalf("unexpected audit count: %d/%d", len(outbox.insertedAudits), len(outbox.wrapperAudits))
	}
}
func TestDeviceRiskAuditRefusalsDoNotClaimApplied(t *testing.T) {
	handler, writer, overlay, _, runtime, _ := deviceRiskAuditHandler(t)
	for _, tc := range []struct {
		id, severity, bearer string
		status               int
	}{
		{"other-device", "high", transportAuditBearer, 404}, {"owned-device", "high", transportAuditReadBearer, 403},
		{"owned-device", "invalid", transportAuditBearer, 400},
	} {
		rec := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"`+tc.id+`","severity":"`+tc.severity+`"}`, tc.bearer)
		if rec.Code != tc.status {
			t.Fatalf("status %d want %d: %s", rec.Code, tc.status, rec.Body)
		}
	}
	if len(overlay.Snapshot()) != 0 {
		t.Fatal("refused request changed overlay")
	}
	for _, d := range runtime.List() {
		if d.Metadata["risk_state_severity"] != nil {
			t.Fatal("refused request changed runtime")
		}
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 3 {
		t.Fatalf("refusal audits %d", len(rows))
	}
	for _, row := range rows {
		if row.EventType == "device_risk_changed" || stringPtrValue(row.Result) == "success" {
			t.Fatal("refusal reported success")
		}
	}
}
func TestDeviceRiskOperatorAuditUsesAffectedTenant(t *testing.T) {
	handler, writer, _, _, _, _ := deviceRiskAuditHandler(t)
	rec := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"other-device","severity":"critical"}`, transportAuditOperatorBearer)
	if rec.Code != 200 {
		t.Fatalf("operator: %d %s", rec.Code, rec.Body)
	}
	count := 0
	for _, row := range readTransportAudits(t, writer) {
		if row.EventType != "device_risk_changed" {
			continue
		}
		count++
		if row.TenantID != "tenant_other" || stringPtrValue(row.ActorUserID) != "transport-operator" || row.Metadata["operator_tenant_id"] != "tenant_lab_001" || stringPtrValue(row.TargetID) != "other-device" {
			t.Fatalf("wrong actor/tenant: %+v", row)
		}
	}
	if count != 1 {
		t.Fatal("missing operator risk audit")
	}
}
func TestDeviceRiskAuditWriterFailureIsObservable(t *testing.T) {
	handler, writer, overlay, outbox, _, _ := deviceRiskAuditHandler(t)
	if err := os.Mkdir(filepath.Join(writer.Dir(), "audit.log.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(previous)
	rec := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"owned-device","severity":"high"}`, transportAuditBearer)
	if rec.Code != 200 || overlay.Snapshot()["owned-device"] != "high" {
		t.Fatal("audit failure changed live risk contract")
	}
	if !strings.Contains(buf.String(), `admin_audit_write_failed event="device_risk_changed"`) {
		t.Fatal("audit failure invisible")
	}
	if len(outbox.insertedAudits) != 0 || len(outbox.wrapperAudits) != 0 {
		t.Fatal("failed primary audit mirrored as written")
	}
}
