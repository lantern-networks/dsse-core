package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
)

func TestAdminExportRuntimeResolverHydratesQueuedTaskFromDocument(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"decision": "allow"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T01:00:00Z",
		Limit:   50,
	}
	store := newAdminExportJobStore()
	job := store.Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	resolver := adminExportRuntimeResolver{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       store,
		Evaluator:   testEvaluator(),
	}

	item, err := resolver.Hydrate(document, "", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Hydrate returned error: %v", err)
	}
	if item.Job.ID != job.ID || item.Document.ID != document.ID {
		t.Fatalf("hydrated item = %#v", item)
	}
	if item.Task.Writer != writer || item.Task.ObjectStore == nil || item.Task.HotStore == nil || item.Task.Store != store {
		t.Fatalf("hydrated runtime deps = %#v", item.Task)
	}
	if item.Task.TenantID != "tenant_lab_001" || item.Task.AdminPrincipalID != "admin_lab_001" || item.Task.SourceIP != "127.0.0.1" {
		t.Fatalf("hydrated identity fields = %#v", item.Task)
	}
	if item.Task.Request.Stream != req.Stream || item.Task.Request.Limit != req.Limit || item.Task.Request.Filters["decision"] != "allow" {
		t.Fatalf("hydrated request = %#v, want %#v", item.Task.Request, req)
	}
	item.Task.Request.Filters["decision"] = "deny"
	if document.Filters["decision"] != "allow" {
		t.Fatalf("document filters mutated through hydrated task: %#v", document.Filters)
	}
}

func TestAdminExportRuntimeResolverUsesTenantScopedJobLookup(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T00:00:00Z", To: "2026-05-23T01:00:00Z"}
	baseStore := newAdminExportJobStore()
	job := baseStore.Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	store := &trackingTenantReaderStore{adminExportJobStore: baseStore}
	resolver := adminExportRuntimeResolver{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       store,
		Evaluator:   testEvaluator(),
	}
	if _, err := resolver.Hydrate(document, "", now.Add(time.Minute)); err != nil {
		t.Fatalf("Hydrate returned error: %v", err)
	}
	if store.getCalled {
		t.Fatalf("resolver used cross-tenant Get instead of GetByTenant")
	}
	if store.tenantLookups != 1 {
		t.Fatalf("tenant lookups = %d, want 1", store.tenantLookups)
	}
}

func TestAdminExportRuntimeResolverHydratesValidatedPayload(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	schemaData := readExportWorkerTaskSchemaForTest(t)
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"decision": "allow"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T01:00:00Z",
		Limit:   50,
	}
	store := newAdminExportJobStore()
	job := store.Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	resolver := adminExportRuntimeResolver{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       store,
		Evaluator:   testEvaluator(),
	}

	item, err := resolver.HydratePayload(payload, schemaData, "127.0.0.2", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("HydratePayload returned error: %v", err)
	}
	if item.Document.ID != document.ID || item.Task.SourceIP != "127.0.0.2" {
		t.Fatalf("hydrated item = %#v", item)
	}
}

func TestDecodeAdminExportWorkerTaskDocumentRejectsInvalidPayload(t *testing.T) {
	schemaData := readExportWorkerTaskSchemaForTest(t)
	if _, err := decodeAdminExportWorkerTaskDocument(nil, schemaData); err == nil || !strings.Contains(err.Error(), "payload is required") {
		t.Fatalf("decode nil payload error = %v", err)
	}
	if _, err := decodeAdminExportWorkerTaskDocument([]byte(`{"id":"export_task_001"}`), schemaData); err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("decode incomplete payload error = %v", err)
	}
	if _, err := decodeAdminExportWorkerTaskDocument([]byte(`{"id":"export_task_001"}`), nil); err == nil || !strings.Contains(err.Error(), "schema is required") {
		t.Fatalf("decode missing schema error = %v", err)
	}
}

func TestAdminExportRuntimeResolverRejectsUnsafeHydration(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T00:00:00Z", To: "2026-05-23T01:00:00Z"}
	store := newAdminExportJobStore()
	job := store.Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	valid := adminExportRuntimeResolver{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       store,
		Evaluator:   testEvaluator(),
	}
	for name, mutate := range map[string]func(adminExportRuntimeResolver, adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string){
		"missing writer": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			resolver.Writer = nil
			return resolver, document, "writer"
		},
		"missing object store": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			resolver.ObjectStore = nil
			return resolver, document, "object store"
		},
		"missing hot store": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			resolver.HotStore = nil
			return resolver, document, "hot store"
		},
		"missing job store": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			resolver.Store = nil
			return resolver, document, "job store"
		},
		"missing tenant": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			document.TenantID = ""
			return resolver, document, "tenant_id"
		},
		"missing job": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			document.ExportJobID = "export_absent"
			return resolver, document, "absent"
		},
		"tenant mismatch": func(resolver adminExportRuntimeResolver, document adminExportWorkerTaskDocument) (adminExportRuntimeResolver, adminExportWorkerTaskDocument, string) {
			document.TenantID = "tenant_other_001"
			return resolver, document, "absent"
		},
	} {
		t.Run(name, func(t *testing.T) {
			resolver, document, want := mutate(valid, document)
			_, err := resolver.Hydrate(document, "127.0.0.1", now)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Hydrate error = %v, want containing %q", err, want)
			}
		})
	}
}

func readExportWorkerTaskSchemaForTest(t *testing.T) []byte {
	t.Helper()
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "export_worker_task.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	return schemaData
}

type trackingTenantReaderStore struct {
	*adminExportJobStore
	getCalled     bool
	tenantLookups int
}

func (s *trackingTenantReaderStore) Get(id string) (adminExportJob, bool) {
	s.getCalled = true
	return adminExportJob{}, false
}

func (s *trackingTenantReaderStore) GetByTenant(ctx context.Context, tenantID, jobID string) (adminExportJob, bool, error) {
	s.tenantLookups++
	return s.adminExportJobStore.GetByTenant(ctx, tenantID, jobID)
}

func (s *trackingTenantReaderStore) ListByTenant(ctx context.Context, tenantID string, limit int) ([]adminExportJob, error) {
	return s.adminExportJobStore.ListByTenant(ctx, tenantID, limit)
}
