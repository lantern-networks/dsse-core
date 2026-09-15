package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestHumanApprovalRuntimeReferencesRespectTenant(t *testing.T) {
	for _, tc := range []struct {
		id, tenant, result string
		want               int
	}{{"own", "tenant_lab_001", "approved", 202}, {"foreign", "tenant_other", "approved", 404}, {"foreign-revoked", "tenant_other", "revoked", 404}, {"expired", "tenant_lab_001", "expired", 403}, {"absent", "", "", 404}} {
		t.Run(tc.id, func(t *testing.T) {
			approvals := newHumanApprovalEventStore()
			if tc.tenant != "" {
				if _, e := approvals.Upsert(model.HumanApprovalEvent{ID: tc.id, TenantID: tc.tenant, ApprovalResult: tc.result, ActorNHIID: stringPtr("agent"), ActionType: stringPtr("read"), CreatedAt: time.Now().Format(time.RFC3339)}); e != nil {
					t.Fatal(e)
				}
			}
			dir := t.TempDir()
			writer, e := logs.NewWriter(dir)
			if e != nil {
				t.Fatal(e)
			}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), HumanApprovals: approvals, Writer: writer})
			get := httptest.NewRecorder()
			h.ServeHTTP(get, httptest.NewRequest("GET", "/human-approvals/events/"+tc.id, nil))
			wantGet := 200
			if tc.tenant != "tenant_lab_001" {
				wantGet = 404
			}
			if get.Code != wantGet {
				t.Errorf("GET %d %s", get.Code, get.Body.String())
			}
			body := fmt.Sprintf(`{"id":"tool-event","tenant_id":"tenant_lab_001","actor_nhi_id":"agent","tool_id":"read","action_type":"read","human_approval_event_id":%q,"result_summary_scope":"metadata_only"}`, tc.id)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", "/tools/events", strings.NewReader(body)))
			if rec.Code != tc.want {
				t.Fatalf("tool reference %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			data, _ := os.ReadFile(filepath.Join(dir, "tool_call_events.log.jsonl"))
			var audits []model.AuditLog
			if _, err := os.Stat(filepath.Join(dir, "audit.log.jsonl")); err == nil {
				audits = readTransportAudits(t, writer)
			}
			if tc.want == 202 {
				if !strings.Contains(string(data), "tool-event") || len(audits) != 1 {
					t.Fatal("accepted event missing")
				}
			} else {
				if len(data) != 0 || len(audits) != 0 {
					t.Fatal("rejected reference recorded accepted event")
				}
			}
		})
	}
}
