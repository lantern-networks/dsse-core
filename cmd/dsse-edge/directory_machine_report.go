package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/internal/strictjson"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// registerDirectoryMachineReportRoute is the CP's machine door for an import
// already accepted from a connector at an Edge. The Edge certificate, its
// explicit tenant authority, the CP's connector registration and the CP's
// source assignment must all agree. An operator bearer is never used here.
func registerDirectoryMachineReportRoute(mux *http.ServeMux, store humanidentity.HumanIdentityDirectoryRuntimeStore,
	registry connectorRegistryStore, tenantCAs *tenantca.TenantCARegistry, configSourceURL string,
	evaluator decision.Evaluator, writer *logs.Writer, auditOutbox adminAuditOutboxDeadReader) {
	if store == nil || registry == nil || strings.TrimSpace(configSourceURL) != "" {
		return
	}
	mux.HandleFunc("POST /directory-import-report", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(captureCPWriteLease(r.Context()))
		shipper, verified := operatorEdgeShipperFrom(r, tenantCAs)
		if !verified {
			writeError(w, http.StatusForbidden, fmt.Errorf("directory import requires a verified Edge certificate"))
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIdentitySourceImportBodyBytes))
		trimmed := bytes.TrimSpace(raw)
		if err != nil || len(trimmed) == 0 || trimmed[0] != '{' || strictjson.RejectDuplicateKeys(raw) != nil ||
			strictjson.RejectUnknownFields(raw, directoryImportReport{}) != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid directory import report"))
			return
		}
		var report directoryImportReport
		if err := json.Unmarshal(raw, &report); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid directory import report"))
			return
		}
		tenantID, connectorID, source := strings.TrimSpace(report.TenantID), strings.TrimSpace(report.ConnectorID), strings.TrimSpace(report.Request.Source)
		if tenantID == "" || connectorID == "" || source == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("directory import requires tenant, connector and source"))
			return
		}
		// Unlike a tenant's endpoint or connector certificate, an Edge relay
		// must be explicitly named by the CP's Edge→tenant authority map.
		// The single-tenant certificate fallback is not an Edge role proof.
		if auditIngestAuthorityMap == nil || !edgeMayShipForTenant(shipper, tenantID) {
			writeError(w, http.StatusForbidden, fmt.Errorf("Edge is not authorized for this tenant"))
			return
		}
		if cpLeaderElectorInstance != nil && !cpLeaderElectorInstance.IsLeader() {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("directory authority is not active"))
			return
		}
		registered := false
		if checked, ok := registry.(connectorRegistryTenantReader); ok {
			_, registered, err = checked.GetByTenant(r.Context(), tenantID, connectorID)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("connector registry is unavailable"))
				return
			}
		} else {
			var connTenant string
			if conn, found := registry.Get(connectorID); found {
				connTenant = conn.TenantID
			}
			registered = connTenant == tenantID
		}
		if !registered {
			writeError(w, http.StatusForbidden, fmt.Errorf("connector is not registered for this tenant"))
			return
		}
		policy, found, err := humanidentity.HumanIdentityDirectorySourcePolicyForSource(r.Context(), store, tenantID, source)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("directory source policy is unavailable"))
			return
		}
		assigned, _ := policy.Metadata["connector_id"].(string)
		if !found || !policy.Enabled || strings.TrimSpace(assigned) != connectorID {
			writeError(w, http.StatusForbidden, fmt.Errorf("directory source is not assigned to this connector"))
			return
		}
		now := time.Now().UTC()
		result, err := humanidentity.HumanIdentityDirectoryImport(r.Context(), store, report.Request, tenantID, now)
		if err != nil {
			if errors.Is(err, humanidentity.ErrDirectoryPersistence) {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("directory import persistence is unavailable"))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		audit := humanIdentityImportAuditLog(result, r, evaluator, now)
		audit.ActorNHIID = &shipper.Identity
		_ = appendAdminAudit(r.Context(), writer, auditOutbox, audit, now)
		writeJSON(w, http.StatusOK, result)
	})
}
