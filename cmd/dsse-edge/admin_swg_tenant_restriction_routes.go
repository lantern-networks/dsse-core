package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

// swgCallerTenant answers which organization a tenant-restriction request acts within, and whether the caller
// is an operator acting across the whole deployment.
func swgCallerTenant(r *http.Request) (tenant string, wholeDeployment bool) {
	return adminAnswerScope(r)
}

// SWG tenant-restriction admin routes (status/write + S6 versions/rollback), moved
// verbatim out of newServerWithConfig (Phase 2 route-registration split). Only mechanical
// change: config.CPVersions became the cpVersions parameter.
func registerSWGTenantRestrictionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, policyStore policy.RuntimeStore, swgRuntime swg.RuntimeConfig, cpVersions *cpConfigVersionClient, configSourceURL string) {
	mux.HandleFunc("GET /admin/swg/tenant-restriction", adminEndpoint("admin.swg.read", func(w http.ResponseWriter, r *http.Request) {
		if err := refreshManagedTenantRestrictions(policyStore); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("SaaS configuration cannot be refreshed: %w", err))
			return
		}
		// Show the runtime-effective bundle (base + SaaS enable/disable overrides) so live toggles are reflected.
		status := swg.TenantRestrictionStatus(swgRuntime, runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle)
		tenant, whole := swgCallerTenant(r)
		scoped := status.ForTenant(tenant, whole)
		if tenant != "" && !whole {
			scoped = scoped.WithManagedProviders(tenant, policyStore.SnapshotTenantConfig(tenant).SaaSTenantRestrictions)
		}
		writeJSON(w, http.StatusOK, scoped)
	}))
	mux.HandleFunc("POST /admin/swg/tenant-restriction", adminEndpoint("admin.swg.write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			swg.TenantRestrictionUpdateRequest
			policy.TenantRestrictionPatch
			Provider string `json:"provider"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		if req.Provider != "" {
			// CP_AUTHORED: POST /admin/swg/tenant-restriction
			if configWriteRejectedWhenSourced(w, configSourceURL, "SaaS tenant restriction configuration") {
				return
			}
			tenant, whole := swgCallerTenant(r)
			if tenant == "" || whole {
				writeError(w, http.StatusBadRequest, fmt.Errorf("select a tenant before configuring SaaS restriction"))
				return
			}
			if len(req.HeaderValueUpdates) > 0 || len(req.SaaSEnablement) > 0 {
				writeError(w, http.StatusBadRequest, fmt.Errorf("cannot mix managed and legacy updates"))
				return
			}
			for _, rule := range evaluator.PolicyBundle.SWGTenantRestrictionRules {
				if (rule.TenantID == tenant || rule.TenantID == "") && rule.Provider == req.Provider && rule.HeaderValueRef != tenantrestriction.Ref(tenant, req.Provider) {
					writeError(w, http.StatusConflict, fmt.Errorf("use the existing provider configuration"))
					return
				}
			}
			store, ok := policyStore.(interface {
				SaveTenantRestriction(string, string, policy.TenantRestrictionPatch) error
			})
			if !ok {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("managed SaaS configuration is unavailable"))
				return
			}
			if err := store.SaveTenantRestriction(tenant, req.Provider, req.TenantRestrictionPatch); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			status := swg.TenantRestrictionStatus(swgRuntime, runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle).ForTenant(tenant, false).WithManagedProviders(tenant, policyStore.SnapshotTenantConfig(tenant).SaaSTenantRestrictions)
			writeJSON(w, http.StatusOK, map[string]any{"persisted": true, "status": status})
			return
		}
		if req.AllowedValue != nil || req.ContextTenantID != nil || req.Enabled != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("provider is required"))
			return
		}

		// ★ Refuse BEFORE applying. Measured as a customer administrator on 2026-08-16: a single POST turned
		// another organization's Google Workspace tenant restriction ON, with a 200 and the rule going active.
		// A partial apply followed by an error would leave the change in place AND report failure.
		status := swg.TenantRestrictionStatus(swgRuntime, runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle)
		callerTenant, isOperator := swgCallerTenant(r)
		if refused := status.UpdateRefusal(req.TenantRestrictionUpdateRequest, callerTenant, isOperator); refused != "" {
			writeError(w, http.StatusNotFound, fmt.Errorf("no tenant-restriction rule %q in this organization", refused))
			return
		}
		resp, err := swg.ApplyTenantRestrictionUpdate(swgRuntime, evaluator.PolicyBundle, policyStore, req.TenantRestrictionUpdateRequest)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// S6: ship the applied REQUEST as a version to the control plane (history + rollback). The request is
		// the re-applicable snapshot; a rollback re-POSTs a prior version's request.
		shipConfigVersionToCP(r, cpVersions, configversion.ResourceTenantRestriction, adminTenantIDFromRequest(r),
			configversion.ActionUpsert, "tenant-restriction update", req)
		writeJSON(w, http.StatusOK, resp)
	}))
	// S6: tenant-restriction history + rollback (Edge-side resource versioned via the control plane).
	mux.HandleFunc("GET /admin/swg/tenant-restriction/versions", adminEndpoint("admin.swg.read", func(w http.ResponseWriter, r *http.Request) {
		if cpVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versions, err := cpVersions.List(r.Context(), configversion.ResourceTenantRestriction, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}))
	mux.HandleFunc("POST /admin/swg/tenant-restriction/rollback", adminEndpoint("admin.swg.write", func(w http.ResponseWriter, r *http.Request) {
		if cpVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		var body struct {
			VersionNo int64 `json:"version_no"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil || body.VersionNo <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("a positive version_no is required"))
			return
		}
		version, ok, err := cpVersions.Get(r.Context(), configversion.ResourceTenantRestriction, adminTenantIDFromRequest(r), body.VersionNo)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("version %d not found", body.VersionNo))
			return
		}
		var req swg.TenantRestrictionUpdateRequest
		if err := json.Unmarshal(version.Payload, &req); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("decode version payload: %w", err))
			return
		}
		// ★ Refuse BEFORE applying. Measured as a customer administrator on 2026-08-16: a single POST turned
		// another organization's Google Workspace tenant restriction ON, with a 200 and the rule going active.
		// A partial apply followed by an error would leave the change in place AND report failure.
		status := swg.TenantRestrictionStatus(swgRuntime, runtimeEvaluatorForPolicyStore(evaluator, policyStore).PolicyBundle)
		callerTenant, isOperator := swgCallerTenant(r)
		if refused := status.UpdateRefusal(req, callerTenant, isOperator); refused != "" {
			writeError(w, http.StatusNotFound, fmt.Errorf("no tenant-restriction rule %q in this organization", refused))
			return
		}
		resp, err := swg.ApplyTenantRestrictionUpdate(swgRuntime, evaluator.PolicyBundle, policyStore, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		shipConfigVersionToCP(r, cpVersions, configversion.ResourceTenantRestriction, adminTenantIDFromRequest(r),
			configversion.ActionRollback, fmt.Sprintf("rolled back to version %d", body.VersionNo), req)
		writeJSON(w, http.StatusOK, map[string]any{"rolled_back_to": body.VersionNo, "tenant_restriction": resp})
	}))
}

func managedTenantRestrictionStoreOrNil(store policy.RuntimeStore) *policy.Store {
	v, _ := store.(*policy.Store)
	return v
}

func refreshManagedTenantRestrictions(store policy.RuntimeStore) error {
	if shared, ok := store.(interface{ RefreshTenantRestrictions() error }); ok {
		return shared.RefreshTenantRestrictions()
	}
	return nil
}
