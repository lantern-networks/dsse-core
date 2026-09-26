package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestExportOperatorAttributionAcrossLifecycle(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	now := time.Now()
	auth := newAdminAuthStore()
	for _, a := range []struct {
		id, tenant string
		roles      []string
	}{{"operator", "operations", []string{"super_admin"}}, {"customer", "customer", []string{"admin"}}} {
		auth.UpsertPrincipal(adminPrincipal{ID: a.id, TenantID: a.tenant, Roles: a.roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: a.id, TenantID: a.tenant, TokenHash: adminTokenHash("synthetic-" + a.id), Roles: a.roles, Scopes: []string{"*"}, CreatedByAdminPrincipalID: a.id, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "operations")
	for _, id := range []string{"operations", "customer"} {
		if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatal(err)
		}
	}
	delegate(t, tenants, "customer", true, false)
	jobs := newAdminExportJobStore()
	queue := newLocalAdminExportTaskQueue()
	worker := localQueuedAdminExportWorker{Queue: queue}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "operations", AdminExportJobs: jobs, AdminExportWorker: worker})
	call := func(who, path string, body any) adminExportJob {
		t.Helper()
		if path == "/admin/export-jobs" {
			m := body.(map[string]any)
			m["from"] = "2026-09-01T00:00:00Z"
			m["to"] = "2026-09-02T00:00:00Z"
		}
		code, raw := operatorEnvelopeCall(t, h, "synthetic-"+who, http.MethodPost, path, "customer", body)
		if code != 200 && code != 202 {
			t.Fatalf("%s %s: %d %s", who, path, code, raw)
		}
		var job adminExportJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			t.Fatal(err)
		}
		return job
	}
	created := call("operator", "/admin/export-jobs", map[string]any{"stream": "access", "format": "ndjson"})
	if !worker.runOne(queue) {
		t.Fatal("worker did not run")
	}
	done, _ := jobs.Get(created.ID)
	if done.Status != "completed" {
		t.Fatalf("worker status %s", done.Status)
	}
	// Persisted job metadata must carry attribution after the original HTTP request ends.
	raw, _ := json.Marshal(done)
	var restored adminExportJob
	json.Unmarshal(raw, &restored)
	failed := adminExportJobAuditLog("admin_export_failed", restored, testEvaluator(), "")
	if failed.Metadata["operator_tenant_id"] != "operations" {
		t.Fatal("worker failure lost operator attribution")
	}
	customerJob := call("customer", "/admin/export-jobs", map[string]any{"stream": "access", "operatorTenantID": "forged", "operator_tenant_id": "forged"})
	call("operator", "/admin/export-jobs/"+customerJob.ID+"/cancel", map[string]any{})
	operatorJob := call("operator", "/admin/export-jobs", map[string]any{"stream": "access"})
	call("customer", "/admin/export-jobs/"+operatorJob.ID+"/cancel", map[string]any{})
	data, err := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var a model.AuditLog
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(a.EventType, "admin_export_") {
			continue
		}
		counts[a.EventType]++
		if a.TenantID != "customer" {
			t.Fatal("audit assigned to operator home")
		}
		if a.ActorUserID == nil {
			t.Fatal("actor absent")
		}
		if *a.ActorUserID == "operator" {
			if a.Metadata["operator_tenant_id"] != "operations" || a.Metadata["operator_principal_id"] != "operator" {
				t.Fatalf("%s lacks operator attribution", a.EventType)
			}
		} else {
			if _, ok := a.Metadata["operator_tenant_id"]; ok {
				t.Fatalf("%s customer inherited operator attribution", a.EventType)
			}
		}
	}
	for event, want := range map[string]int{"admin_export_requested": 3, "admin_export_task_enqueued": 3, "admin_export_started": 1, "admin_export_completed": 1, "admin_export_cancelled": 2} {
		if counts[event] != want {
			t.Fatalf("%s count %d", event, counts[event])
		}
	}
	pending := jobs.Create(adminExportJobRequest{Stream: "access"}, "customer", "customer", now)
	delegate(t, tenants, "customer", false, false)
	if code, _ := operatorEnvelopeCall(t, h, "synthetic-operator", http.MethodPost, "/admin/export-jobs", "customer", map[string]any{"stream": "access"}); code != 403 {
		t.Fatalf("undelegated create: %d", code)
	}
	if code, _ := operatorEnvelopeCall(t, h, "synthetic-operator", http.MethodPost, "/admin/export-jobs/"+pending.ID+"/cancel", "customer", map[string]any{}); code != 403 {
		t.Fatalf("undelegated cancel: %d", code)
	}
	if live, _ := jobs.Get(pending.ID); live.Status != "queued" {
		t.Fatal("denied cancel changed job")
	}
	foreign := jobs.Create(adminExportJobRequest{Stream: "access"}, "other", "other", now)
	if code, _ := operatorEnvelopeCall(t, h, "synthetic-customer", http.MethodPost, "/admin/export-jobs/"+foreign.ID+"/cancel", "other", map[string]any{}); code != 403 {
		t.Fatalf("cross-tenant cancel: %d", code)
	}
}
