package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	schemavalidator "github.com/lantern-networks/dsse-core/schema"
)

type adminExportRuntimeResolver struct {
	Writer           *logs.Writer
	AdminAuditOutbox adminAuditOutboxDeadReader
	ObjectStore      adminExportObjectStore
	HotStore         hotstore.Store
	Store            adminExportJobRuntimeStore
	Evaluator        decision.Evaluator
}

func (resolver adminExportRuntimeResolver) Hydrate(document adminExportWorkerTaskDocument, sourceIP string, now time.Time) (adminExportQueuedTask, error) {
	if resolver.Writer == nil {
		return adminExportQueuedTask{}, fmt.Errorf("export log writer is not configured")
	}
	if resolver.ObjectStore == nil {
		return adminExportQueuedTask{}, fmt.Errorf("export object store is not configured")
	}
	if resolver.HotStore == nil {
		return adminExportQueuedTask{}, fmt.Errorf("hot store is not configured")
	}
	if resolver.Store == nil {
		return adminExportQueuedTask{}, fmt.Errorf("export job store is not configured")
	}
	if strings.TrimSpace(document.TenantID) == "" {
		return adminExportQueuedTask{}, fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(document.ExportJobID) == "" {
		return adminExportQueuedTask{}, fmt.Errorf("export_job_id is required")
	}
	job, err := resolver.exportJobForTask(document)
	if err != nil {
		return adminExportQueuedTask{}, err
	}
	if strings.TrimSpace(sourceIP) == "" && document.SourceIP != nil {
		sourceIP = strings.TrimSpace(*document.SourceIP)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	request := adminExportJobRequestFromWorkerTaskDocument(document)
	task := adminExportTask{
		Writer:           resolver.Writer,
		AdminAuditOutbox: resolver.AdminAuditOutbox,
		ObjectStore:      resolver.ObjectStore,
		HotStore:         resolver.HotStore,
		Store:            resolver.Store,
		Evaluator:        resolver.Evaluator,
		Request:          request,
		TenantID:         document.TenantID,
		AdminPrincipalID: document.CreatedByAdminPrincipalID,
		SourceIP:         sourceIP,
		Now:              now.UTC(),
	}
	return adminExportQueuedTask{Document: document, Task: task, Job: job}, nil
}

func (resolver adminExportRuntimeResolver) exportJobForTask(document adminExportWorkerTaskDocument) (adminExportJob, error) {
	if reader, ok := resolver.Store.(adminExportJobTenantReader); ok {
		job, found, err := adminExportJobGetForTenantReader(reader, document.TenantID, document.ExportJobID)
		if err != nil {
			return adminExportJob{}, err
		}
		if !found {
			return adminExportJob{}, fmt.Errorf("export job %s is absent", document.ExportJobID)
		}
		return job, nil
	}
	job, ok := resolver.Store.Get(document.ExportJobID)
	if !ok {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", document.ExportJobID)
	}
	if job.TenantID != document.TenantID {
		return adminExportJob{}, fmt.Errorf("export job tenant_id %s does not match task tenant_id %s", job.TenantID, document.TenantID)
	}
	return job, nil
}

func (resolver adminExportRuntimeResolver) HydratePayload(payload []byte, schemaData []byte, sourceIP string, now time.Time) (adminExportQueuedTask, error) {
	document, err := decodeAdminExportWorkerTaskDocument(payload, schemaData)
	if err != nil {
		return adminExportQueuedTask{}, err
	}
	return resolver.Hydrate(document, sourceIP, now)
}

func decodeAdminExportWorkerTaskDocument(payload []byte, schemaData []byte) (adminExportWorkerTaskDocument, error) {
	if len(payload) == 0 {
		return adminExportWorkerTaskDocument{}, fmt.Errorf("export worker task payload is required")
	}
	if len(schemaData) == 0 {
		return adminExportWorkerTaskDocument{}, fmt.Errorf("export worker task schema is required")
	}
	if err := schemavalidator.ValidateRequired(schemaData, payload); err != nil {
		return adminExportWorkerTaskDocument{}, fmt.Errorf("validate export worker task payload: %w", err)
	}
	var document adminExportWorkerTaskDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return adminExportWorkerTaskDocument{}, fmt.Errorf("decode export worker task payload: %w", err)
	}
	return document, nil
}
