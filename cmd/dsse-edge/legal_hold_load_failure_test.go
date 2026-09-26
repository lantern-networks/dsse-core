package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

type unreadableHoldPersister struct {
	data  []byte
	err   error
	saves int
}

func (p *unreadableHoldPersister) Load() ([]byte, error) { return p.data, p.err }
func (p *unreadableHoldPersister) Save([]byte) error     { p.saves++; return nil }

func TestLegalHoldLoadFailurePreservesDataAndReportsUnavailable(t *testing.T) {
	for _, kind := range []string{"read_error", "malformed", "null", "missing_tenant", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			p := &unreadableHoldPersister{}
			switch kind {
			case "read_error":
				p.err = errors.New("private-database-location")
			case "malformed":
				p.data = []byte(`{"broken":`)
			case "null":
				p.data = []byte(`null`)
			case "missing_tenant":
				p.data = []byte(`[{"reason":"private-case-reason"}]`)
			case "duplicate":
				p.data = []byte(`[{"tenant_id":"tenant_lab_001"},{"tenant_id":"tenant_lab_001"}]`)
			}
			holds := newLegalHoldStore(p)
			if holds.Health() == nil {
				t.Fatal("unreadable state reported healthy")
			}
			for _, tenant := range []string{"tenant_lab_001", "another-tenant"} {
				if !holds.IsHeld(tenant) {
					t.Fatal("unknown hold state permits erasure")
				}
			}
			if err := holds.Set("tenant_lab_001", "test", "", false, time.Now()); err == nil {
				t.Fatal("release accepted without loaded state")
			}
			// No database operations are allowed while protection state is unknown.
			runRetentionPrune(context.Background(), nil, retentionConfig{legalHold: holds, hotEvents: time.Hour, outboxPublished: time.Hour, outboxDead: time.Hour})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tenants := newAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now())
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, LegalHold: holds, TenantModelStore: tenants})
			for _, method := range []string{"GET", "POST"} {
				req := httptest.NewRequest(method, "/admin/legal-hold", strings.NewReader(`{"active":false}`))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("%s status=%d", method, rec.Code)
				}
				if strings.Contains(rec.Body.String(), "private-") {
					t.Fatal("storage or case detail leaked")
				}
			}
			for _, operation := range []struct{ method, path, body string }{
				{"DELETE", "/admin/tenants/tenant_lab_001", ""},
				{"POST", "/admin/tenants/absent-tenant/purge", `{"confirm_tenant_id":"absent-tenant"}`},
			} {
				req := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 503 {
					t.Fatalf("erasure %s status=%d body=%s", operation.path, rec.Code, rec.Body.String())
				}
			}
			if _, err := tenants.Get(context.Background(), "tenant_lab_001"); err != nil {
				t.Fatal("tenant deleted despite unknown protection state")
			}
			if p.saves != 0 {
				t.Fatal("unreadable snapshot overwritten")
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row["event_type"] == "admin_config_change" && row["target_id"] == "/admin/legal-hold" {
					found = true
					if row["result"] != "error" {
						t.Fatal("failed release audited as success")
					}
				}
			}
			if !found {
				t.Fatal("failed release audit missing")
			}
			// Repair does not silently unlock this running store. A clean reload restores authority.
			p.err = nil
			p.data = []byte(`[{"tenant_id":"tenant_lab_001"}]`)
			if holds.Health() == nil {
				t.Fatal("load failure spontaneously cleared")
			}
			restored := newLegalHoldStore(p)
			if restored.Health() != nil || !restored.IsHeld("tenant_lab_001") || restored.IsHeld("another-tenant") {
				t.Fatal("repaired store did not reload original protection")
			}
		})
	}
}
