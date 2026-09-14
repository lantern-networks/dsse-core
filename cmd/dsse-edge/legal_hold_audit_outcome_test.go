package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

type holdOutcomePersister struct {
	data []byte
	fail bool
}

func (p *holdOutcomePersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *holdOutcomePersister) Save(data []byte) error {
	if p.fail {
		return fmt.Errorf("simulated storage failure")
	}
	p.data = bytes.Clone(data)
	return nil
}

func TestLegalHoldHTTPOutcomeAndAudit(t *testing.T) {
	for _, initiallyHeld := range []bool{false, true} {
		for _, failSave := range []bool{false, true} {
			t.Run(fmt.Sprintf("held=%t/fail=%t", initiallyHeld, failSave), func(t *testing.T) {
				p := &holdOutcomePersister{}
				holds := newLegalHoldStore(p)
				tenant := testEvaluator().PolicyBundle.TenantID
				if initiallyHeld {
					holds.Set(tenant, "original-admin", "original reason", true, time.Now())
					if !holds.IsHeld(tenant) {
						t.Fatal("fixture hold not established")
					}
				}
				p.fail = failSave
				writer, err := logs.NewWriter(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), LegalHold: holds})
				body := fmt.Sprintf(`{"active":%t,"reason":"synthetic-case-reason-not-for-audit"}`, !initiallyHeld)
				req := httptest.NewRequest(http.MethodPost, "/admin/legal-hold", strings.NewReader(body))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				wantStatus, wantHeld, wantResult := 200, !initiallyHeld, "success"
				if failSave {
					wantStatus, wantHeld, wantResult = 500, initiallyHeld, "error"
				}
				if rec.Code != wantStatus {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				if holds.IsHeld(tenant) != wantHeld {
					t.Fatal("in-memory hold disagrees with outcome")
				}
				if newLegalHoldStore(p).IsHeld(tenant) != wantHeld {
					t.Fatal("reloaded hold disagrees with outcome")
				}
				rows, err := writer.ReadJSONL("audit.log.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, row := range rows {
					if row["event_type"] != "admin_config_change" {
						continue
					}
					count++
					if row["tenant_id"] != tenant || row["target_id"] != "/admin/legal-hold" || row["result"] != wantResult || row["action"] != "POST" {
						t.Fatalf("wrong mutation audit: %#v", row)
					}
					if row["actor_user_id"] == nil || row["actor_user_id"] == "" || row["timestamp"] == nil {
						t.Fatalf("missing audit attribution: %#v", row)
					}
					encoded, _ := json.Marshal(row)
					if bytes.Contains(encoded, []byte("synthetic-case-reason")) {
						t.Fatal("audit leaked authored reason")
					}
				}
				if count != 1 {
					t.Fatalf("expected one wrapper audit, got %d", count)
				}
			})
		}
	}
}

func TestLegalHoldMissingTenantIsForbidden(t *testing.T) {
	p := &holdOutcomePersister{}
	holds := newLegalHoldStore(p)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	evaluator := testEvaluator()
	evaluator.PolicyBundle.TenantID = ""
	handler := newServerWithConfig(serverConfig{Evaluator: evaluator, Writer: writer, Registry: connector.NewRegistry(), LegalHold: holds})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/legal-hold", strings.NewReader(`{"active":true}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if p.data != nil || len(holds.List()) != 0 {
		t.Fatal("unscoped operation changed state")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["event_type"] != "admin_config_change" || rows[0]["metadata"].(map[string]any)["status_code"] != float64(403) {
		t.Fatalf("wrong audit: %#v", rows)
	}
}
