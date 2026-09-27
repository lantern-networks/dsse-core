package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tenantPurgeSaveStore struct {
	base           blobstore.Persister
	fail, bridge   bool
	failAt, writes int
}

func (p *tenantPurgeSaveStore) Load() ([]byte, error) { return p.base.Load() }
func (p *tenantPurgeSaveStore) Save(b []byte) error {
	p.writes++
	failed := p.fail || (p.failAt > 0 && p.writes == p.failAt)
	if failed && !p.bridge {
		return errors.New("private store path")
	}
	if err := p.base.Save(b); err != nil {
		return err
	}
	if failed {
		return errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	}
	return nil
}
func TestTenantDeletionPurgeSaveRetryAndAudit(t *testing.T) {
	for _, kind := range []string{"healthy", "admission_no_write", "admission_bridge", "retirement_no_write", "retirement_bridge", "ledger_erasure_no_write", "ledger_erasure_bridge", "risk_device_no_write", "risk_device_bridge", "risk_combined_no_write", "risk_combined_bridge"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC()
			stamp := now.Format(time.RFC3339)
			tenantStore := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, now, filepath.Join(dir, "tenants.json"), "tenant_lab_001")
			for _, id := range []string{"tenant_gone", "tenant_other"} {
				if _, err := tenantStore.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
					t.Fatal(err)
				}
			}
			lp := &tenantPurgeSaveStore{base: blobstore.FilePersister{Path: filepath.Join(dir, "ledger.json")}}
			ap := &tenantPurgeSaveStore{base: blobstore.FilePersister{Path: filepath.Join(dir, "admission.json")}}
			rp := &tenantPurgeSaveStore{base: blobstore.FilePersister{Path: filepath.Join(dir, "risk.json")}}
			risk := revocation.NewHighRiskOverlay()
			risk.SetPersister(rp)
			ledger := enrolledinventory.NewLedger()
			ledger.SetPersister(lp)
			a := revocation.NewAdmissionRevocations()
			if err := a.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			for _, x := range []struct{ id, tenant string }{{"own", "tenant_gone"}, {"foreign", "tenant_other"}} {
				if _, err := ledger.Enroll(x.id, x.tenant, "", stamp); err != nil {
					t.Fatal(err)
				}
				a.Revoke(x.id, "original")
				risk.Mark(x.id, "high")
			}
			for _, tenant := range []string{"tenant_gone", "tenant_other"} {
				if tenant == "tenant_gone" && strings.HasPrefix(kind, "risk_device") {
					continue
				}
				if _, err := risk.SetUserRisk(revocation.UserRisk{TenantID: tenant, ID: "shared", Severity: "critical"}); err != nil {
					t.Fatal(err)
				}
			}
			a.RevokeFromMesh("peer-kept", "peer")
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "tenant_lab_001", Roles: []string{"owner"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "operator", Roles: []string{"owner"}, Scopes: []string{"*"}, Status: "active", TokenHash: adminTokenHash("synthetic-tenant-removal"), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			handler := func() http.Handler {
				return newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, TenantModelStore: tenantStore, OperatorTenantID: "tenant_lab_001", EnrolledLedger: ledger, AdmissionRevocations: a, HighRiskOverlay: risk})
			}
			send := func(method, path string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, strings.NewReader(`{"confirm_tenant_id":"tenant_gone"}`))
				r.Header.Set("authorization", "Bearer synthetic-tenant-removal")
				w := httptest.NewRecorder()
				handler().ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
				}
				return w
			}
			if strings.HasPrefix(kind, "retirement") {
				lp.fail = true
				lp.bridge = strings.HasSuffix(kind, "bridge")
			}
			deleted := send("DELETE", "/admin/tenants/tenant_gone")
			if !strings.Contains(deleted.Body.String(), `"deleted":true`) {
				t.Fatal("missing deletion ack")
			}
			own, exists := ledger.EntryFor("own")
			if !exists || own.Enabled || own.RemovedAt == "" {
				t.Fatal("deletion lost retry attribution or kept admission")
			}
			if strings.HasPrefix(kind, "admission") {
				ap.fail = true
				ap.bridge = strings.HasSuffix(kind, "bridge")
			}
			if strings.HasPrefix(kind, "ledger_erasure") {
				lp.failAt = lp.writes + 2
				lp.bridge = strings.HasSuffix(kind, "bridge")
			}
			if strings.HasPrefix(kind, "risk_") {
				rp.fail = true
				rp.bridge = strings.HasSuffix(kind, "bridge")
			}
			first := send("POST", "/admin/tenants/tenant_gone/purge")
			var result adminTenantPurgeResult
			if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Complete != (kind == "healthy") {
				t.Fatalf("false completeness %+v", result)
			}
			if kind != "healthy" {
				if len(result.Failures) == 0 {
					t.Fatal("missing failure")
				}
				for _, row := range result.Erased {
					if (strings.HasPrefix(kind, "admission") && row.Store == "admission_kill_switches") || (row.Store == "enrolled_identities") || (strings.HasPrefix(kind, "risk_") && row.Store == "high_risk_marks") {
						t.Fatal("unconfirmed erasure reported as erased")
					}
				}
			}
			if strings.HasPrefix(kind, "admission") {
				if a.Snapshot()["own"] != "original" || ledger.CountTenantRecords("tenant_gone") != 1 {
					t.Fatal("failed cleanup lost live state/attribution")
				}
			}
			if strings.HasPrefix(kind, "risk_") {
				if risk.Snapshot()["own"] != "high" || ledger.CountTenantRecords("tenant_gone") != 1 {
					t.Fatal("risk failure lost live marks or ownership")
				}
				if strings.HasPrefix(kind, "risk_combined") && risk.CountUsers("tenant_gone") != 1 {
					t.Fatal("partial user/device erasure")
				}
			}
			rp.fail = false
			lp.fail = false
			lp.failAt = 0
			ap.fail = false
			// Reconstruct both persisted stores. Retirement failure is reconciled first:
			// its old saved inventory may still be enabled after an ambiguous write.
			if strings.HasPrefix(kind, "retirement") {
				if _, err := ledger.RetireTenantChecked("tenant_gone", stamp); err != nil {
					t.Fatal(err)
				}
			}
			ledger = enrolledinventory.NewLedger()
			if err := ledger.SetPersisterChecked(lp); err != nil {
				t.Fatal(err)
			}
			a = revocation.NewAdmissionRevocations()
			if err := a.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			if ledger.IsAdmitted("own") {
				t.Fatal("retired identity re-admitted on reload")
			}
			risk = revocation.NewHighRiskOverlay()
			risk.SetPersister(rp)
			last := send("POST", "/admin/tenants/tenant_gone/purge")
			if err := json.Unmarshal(last.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !result.Complete || result.Remaining.Total != 0 || ledger.CountTenantRecords("tenant_gone") != 0 {
				t.Fatalf("retry incomplete %+v", result)
			}
			if _, ok := a.Snapshot()["own"]; ok {
				t.Fatal("retry left origin block")
			}
			if a.Snapshot()["foreign"] != "original" || !ledger.IsAdmitted("foreign") || a.FeedSnapshot()["peer-kept"] != "peer" {
				t.Fatal("foreign/mesh changed")
			}
			if risk.Snapshot()["own"] != "" || risk.CountUsers("tenant_gone") != 0 || risk.Snapshot()["foreign"] != "high" || risk.CountUsers("tenant_other") != 1 {
				t.Fatal("risk erasure or isolation failed")
			}
			data, err := os.ReadFile(filepath.Join(dir, "logs", "audit.log.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "private store path") || strings.Contains(string(data), "synthetic-tenant-removal") {
				t.Fatal("audit leaked secrets")
			}
			domain := []map[string]any{}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var row map[string]any
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(fmtString(row["event_type"]), "admin_tenant_model_") {
					domain = append(domain, row)
				}
			}
			if len(domain) != 3 {
				t.Fatalf("domain audit count %d", len(domain))
			}
			for _, row := range domain {
				if row["tenant_id"] != "tenant_lab_001" || row["target_id"] != "tenant_gone" || row["metadata"].(map[string]any)["actor_admin_principal_id"] != "operator" {
					t.Fatal("wrong audit ownership")
				}
			}
			expected := "success"
			if kind != "healthy" {
				expected = "partial"
			}
			if domain[1]["result"] != expected || domain[2]["result"] != "success" {
				t.Fatal("audit success despite incomplete purge")
			}
			if strings.HasPrefix(kind, "retirement") && domain[0]["result"] != "partial" {
				t.Fatal("failed retirement deletion audit succeeded")
			}
		})
	}
}
func fmtString(v any) string { s, _ := v.(string); return s }
