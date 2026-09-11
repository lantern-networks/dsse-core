package main

import (
	"fmt"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"
)

func humanIdentityDirectoryListOptionsFromRequest(r *http.Request) (humanidentity.HumanIdentityDirectoryListOptions, error) {
	query := r.URL.Query()
	option := humanidentity.HumanIdentityDirectoryListOptions{
		Source:      strings.TrimSpace(query.Get("source")),
		Status:      strings.TrimSpace(query.Get("status")),
		Subject:     strings.TrimSpace(query.Get("subject")),
		Email:       strings.TrimSpace(query.Get("email")),
		ImportRunID: strings.TrimSpace(query.Get("import_run_id")),
		Limit:       boundedIntQuery(query.Get("limit"), 200, 1, 1000),
	}
	afterID, err := humanidentity.DecodeHumanIdentityDirectoryCursor(query.Get("cursor"))
	if err != nil {
		return humanidentity.HumanIdentityDirectoryListOptions{}, err
	}
	option.AfterID = afterID
	if option.Status != "" && !humanidentity.HumanIdentityStatusAllowed(option.Status) {
		return humanidentity.HumanIdentityDirectoryListOptions{}, fmt.Errorf("unsupported human identity status %q", option.Status)
	}
	return option, nil
}

// Human-identity directory admin routes (list/sources/policies/import-runs/upsert/import)
// plus the two connector-facing identity-source endpoints, moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Parameter names match the
// constructor's locals so the handler bodies are untouched.
func registerHumanIdentityRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, humanIdentities humanidentity.HumanIdentityDirectoryRuntimeStore, adminAuditOutbox adminAuditOutboxDeadReader, registry connectorRegistryStore, connectorSecret string, devMode bool, requireConnectorRuntimeSecret bool, configSourceURL string, directoryReporter *directoryCPReporter, tenantCAs *tenantca.TenantCARegistry) {
	mux.HandleFunc("GET /admin/human-identities", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		options, err := humanIdentityDirectoryListOptionsFromRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		result, err := humanidentity.HumanIdentityDirectoryList(r.Context(), humanIdentities, adminTenantIDFromRequest(r), time.Now(), options)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/sources", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := humanidentity.HumanIdentityDirectorySourceList(r.Context(), humanIdentities, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/sources/policies", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := humanidentity.HumanIdentityDirectorySourcePolicyList(r.Context(), humanIdentities, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/sources/due", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := humanidentity.HumanIdentityDirectorySourceDueList(r.Context(), humanIdentities, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/sources/state", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := humanidentity.HumanIdentityDirectorySourceStateList(r.Context(), humanIdentities, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/sources/health", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		staleAfterSeconds := boundedIntQuery(r.URL.Query().Get("stale_after_seconds"), 24*60*60, 60, 30*24*60*60)
		result, err := humanidentity.HumanIdentityDirectorySourceHealth(r.Context(), humanIdentities, adminTenantIDFromRequest(r), time.Now(), time.Duration(staleAfterSeconds)*time.Second)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/import-runs", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		options := humanidentity.HumanIdentityImportRunListOptions{
			Limit:  boundedIntQuery(r.URL.Query().Get("limit"), 25, 1, 1000),
			Source: strings.TrimSpace(r.URL.Query().Get("source")),
		}
		result, err := humanidentity.HumanIdentityDirectoryImportRunList(r.Context(), humanIdentities, adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/human-identities/import-runs/{import_run_id}", adminEndpoint("admin.identity.read", func(w http.ResponseWriter, r *http.Request) {
		result, found, err := humanidentity.HumanIdentityDirectoryImportRunDetail(r.Context(), humanIdentities, adminTenantIDFromRequest(r), r.PathValue("import_run_id"))
		if err != nil {
			if strings.Contains(err.Error(), "import_run_id") {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("human identity import run %s is absent", r.PathValue("import_run_id")))
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("POST /admin/human-identities", adminEndpoint("admin.identity.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "the people directory") {
			return
		}
		var identity model.HumanIdentity
		if err := decodeLimitedJSONBody(w, r, &identity, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human identity: %w", err))
			return
		}
		now := time.Now()
		created, err := humanIdentities.Upsert(r.Context(), identity, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, humanIdentityAuditLog(created, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, created)
	}))
	mux.HandleFunc("POST /admin/human-identities/sources/policies", adminEndpoint("admin.identity.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "identity source policies") {
			return
		}
		var policy humanidentity.HumanIdentitySourcePolicy
		if err := decodeLimitedJSONBody(w, r, &policy, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human identity source policy: %w", err))
			return
		}
		now := time.Now()
		created, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(r.Context(), humanIdentities, adminTenantIDFromRequest(r), policy, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, humanIdentitySourcePolicyAuditLog(created, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, created)
	}))
	mux.HandleFunc("POST /admin/human-identities/import", adminEndpoint("admin.identity.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "the people directory") {
			return
		}
		var request humanidentity.HumanIdentityDirectoryImportRequest
		if err := decodeLimitedJSONBody(w, r, &request, maxIdentitySourceImportBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human identity import: %w", err))
			return
		}
		now := time.Now()
		result, err := humanidentity.HumanIdentityDirectoryImport(r.Context(), humanIdentities, request, adminTenantIDFromRequest(r), now)
		if err != nil {
			humanidentity.HumanIdentityDirectoryRecordSourceImportError(r.Context(), humanIdentities, request, adminTenantIDFromRequest(r), err, now)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, humanIdentityImportAuditLog(result, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /identity-sources/due", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, tenantCAs) {
			return
		}
		connectorID := strings.TrimSpace(r.Header.Get(connectorIDHeader))
		if !devMode && connectorID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("connector id is required"))
			return
		}
		result, err := humanidentity.HumanIdentityDirectorySourceDueList(r.Context(), humanIdentities, evaluator.PolicyBundle.TenantID, time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity directory is unavailable"))
			return
		}
		result = humanidentity.HumanIdentityDirectorySourceDueListForConnector(result, connectorID)
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("POST /identity-sources/import", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, connectorSecret, devMode, registry, evaluator.PolicyBundle.TenantID, requireConnectorRuntimeSecret, tenantCAs) {
			return
		}
		connectorID := strings.TrimSpace(r.Header.Get(connectorIDHeader))
		if !devMode && connectorID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("connector id is required"))
			return
		}
		// ★ THE CONNECTOR'S DOOR STAYS OPEN, AND IT IS THE ONLY ONE IT HAS (operator, 2026-08-19). A connector
		// lives INSIDE the customer's network and reaches the Edge and nothing else — it cannot be pointed at
		// the control plane. Refusing here, as this handler briefly did, removed the only channel a customer
		// has for syncing their own directory.
		//
		// The authority question is answered by RELAYING instead of refusing: the import is applied here so it
		// takes effect immediately, and the same request is carried to the control plane, which is what makes
		// the rest of the fleet — and the Console, and the seat count — see the same people. That is the shape
		// POST /enroll already uses (enrolment_cp_report.go): a durable outbox, never failing the caller,
		// because the obligation must outlive a control plane that is briefly away.
		var request humanidentity.HumanIdentityDirectoryImportRequest
		if err := decodeLimitedJSONBody(w, r, &request, maxIdentitySourceImportBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode human identity import: %w", err))
			return
		}
		if allowed, err := humanidentity.HumanIdentityDirectorySourceAllowedForConnector(r.Context(), humanIdentities, evaluator.PolicyBundle.TenantID, request.Source, connectorID); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("human identity source policy is unavailable"))
			return
		} else if !allowed {
			writeError(w, http.StatusForbidden, fmt.Errorf("human identity source %q is not assigned to connector %q", request.Source, connectorID))
			return
		}
		now := time.Now()
		result, err := humanidentity.HumanIdentityDirectoryImport(r.Context(), humanIdentities, request, evaluator.PolicyBundle.TenantID, now)
		if err != nil {
			humanidentity.HumanIdentityDirectoryRecordSourceImportError(r.Context(), humanIdentities, request, evaluator.PolicyBundle.TenantID, err, now)
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, humanIdentityImportAuditLog(result, r, evaluator, now), now)
		// Carry it to the authority. Applied above so it is already enforcing here; reported here so the
		// control plane, and through it every other Edge and the Console, hold the same people.
		directoryReporter.Report(directoryImportReport{Request: request, TenantID: evaluator.PolicyBundle.TenantID})
		writeJSON(w, http.StatusOK, result)
	})
}
