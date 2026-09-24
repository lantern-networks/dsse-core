package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/catalogfeed"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
)

// Predefined SaaS-catalog admin routes (read, signed feed apply/rollback, overrides).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerPredefinedCatalogRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer) {
	mux.HandleFunc("GET /admin/predefined-catalog", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogOverrides == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog overrides are not configured on this edge"))
			return
		}
		if !refreshCatalogOverrides(w, config) {
			return
		}
		tenant := adminTenantIDFromRequest(r)
		// Effective catalog = the applied signed feed if one is in force, else the built-in default.
		cat := knownbypass.Catalog()
		source := "builtin"
		if config.CatalogFeed != nil {
			status := config.CatalogFeed.Status(time.Now().UTC())
			if status.Current != nil {
				cat = knownbypass.CatalogDocument{Version: status.Current.CatalogVersion, Entries: status.Current.Entries}
				source = "feed"
			}
		}
		writeCatalogContextResponse(w, r, "tenant", map[string]any{
			"version":                cat.Version,
			"source":                 source,
			"entries":                cat.Entries,
			"overrides":              config.CatalogOverrides.List(tenant),
			"effective_bypass_hosts": config.CatalogOverrides.EffectiveBypassHostsFrom(cat.Entries, tenant),
		})
	}))
	// Signed predefined-catalog FEED admin: apply a vendor-signed catalog, view feed status + version history,
	// and roll back to a prior version. The feed replaces the built-in default when valid; an invalid/older/
	// expired feed is rejected and the current catalog is kept (last-known-good).
	mux.HandleFunc("GET /admin/predefined-catalog/feed", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogFeed == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog feed is not configured on this edge"))
			return
		}
		writeCatalogContextResponse(w, r, "deployment", config.CatalogFeed.Status(time.Now().UTC()))
	}))
	mux.HandleFunc("POST /admin/predefined-catalog/feed", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogFeed == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog feed is not configured on this edge"))
			return
		}
		// ★★ THE CATALOG IS THE NODE'S, AND A CUSTOMER COULD ROLL IT BACK (2026-08-18). The bypass catalog says
		// which destinations are NOT decrypted; it is one document for the whole node, with no tenant in it, so
		// changing it changes what is inspected for every organization on this Edge.
		//
		// Applying a feed is signature-verified and version-monotonic, which is a real wall. ROLLBACK has
		// neither: it names a version already in the history and installs it, so a customer holding
		// admin.policy.write — every tenant administrator — could put the deployment back onto an older bypass
		// set. "Signed" was doing the work for one route and nothing for the one beside it.
		//
		// Gated here rather than by moving admin.policy.write, because the same scope carries the per-tenant
		// OVERRIDES below, which are a customer's own choice about their own organization. Taking that away to
		// close this would be closing an operator hole by removing a customer's right.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"the predefined catalog is one document for this deployment, not per organization, so it is the "+
					"operator's to change; your organization's exceptions are at /admin/predefined-catalog/overrides"))
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxEdgeRuntimeJSONBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read feed envelope: %w", err))
			return
		}
		applied, err := config.CatalogFeed.Apply(raw, time.Now().UTC())
		if err != nil {
			if errors.Is(err, catalogfeed.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("catalog feed save could not be confirmed; reload and retry"))
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if config.ApplyMaterializedCertPinBypass != nil {
			config.ApplyMaterializedCertPinBypass(adminTenantIDFromRequest(r))
		}
		writeCatalogContextResponse(w, r, "deployment", applied)
	}))
	mux.HandleFunc("POST /admin/predefined-catalog/feed/rollback", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogFeed == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog feed is not configured on this edge"))
			return
		}
		// ★★ THE CATALOG IS THE NODE'S, AND A CUSTOMER COULD ROLL IT BACK (2026-08-18). The bypass catalog says
		// which destinations are NOT decrypted; it is one document for the whole node, with no tenant in it, so
		// changing it changes what is inspected for every organization on this Edge.
		//
		// Applying a feed is signature-verified and version-monotonic, which is a real wall. ROLLBACK has
		// neither: it names a version already in the history and installs it, so a customer holding
		// admin.policy.write — every tenant administrator — could put the deployment back onto an older bypass
		// set. "Signed" was doing the work for one route and nothing for the one beside it.
		//
		// Gated here rather than by moving admin.policy.write, because the same scope carries the per-tenant
		// OVERRIDES below, which are a customer's own choice about their own organization. Taking that away to
		// close this would be closing an operator hole by removing a customer's right.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"the predefined catalog is one document for this deployment, not per organization, so it is the "+
					"operator's to change; your organization's exceptions are at /admin/predefined-catalog/overrides"))
			return
		}
		var body struct {
			CatalogVersion int `json:"catalog_version"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode rollback request: %w", err))
			return
		}
		applied, err := config.CatalogFeed.Rollback(body.CatalogVersion, time.Now().UTC())
		if err != nil {
			if errors.Is(err, catalogfeed.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("catalog feed save could not be confirmed; reload and retry"))
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if config.ApplyMaterializedCertPinBypass != nil {
			config.ApplyMaterializedCertPinBypass(adminTenantIDFromRequest(r))
		}
		writeCatalogContextResponse(w, r, "deployment", applied)
	}))
	mux.HandleFunc("POST /admin/predefined-catalog/overrides", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogOverrides == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog overrides are not configured on this edge"))
			return
		}
		var req knownbypass.Override
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode catalog override request: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		var o knownbypass.Override
		var err error
		if config.CatalogFeed != nil {
			o, err = config.CatalogFeed.SetOverrideContext(r.Context(), config.CatalogOverrides, tenant, req, time.Now().UTC())
		} else {
			o, err = config.CatalogOverrides.SetContext(r.Context(), tenant, req, time.Now().UTC())
		}
		if err != nil {
			if errors.Is(err, knownbypass.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("catalog override save could not be confirmed; reload and retry"))
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if config.ApplyMaterializedCertPinBypass != nil {
			config.ApplyMaterializedCertPinBypass(tenant)
		}
		writeCatalogContextResponse(w, r, "tenant", o)
	}))
	mux.HandleFunc("POST /admin/predefined-catalog/overrides/{id}/clear", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if config.CatalogOverrides == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("predefined catalog overrides are not configured on this edge"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		id := strings.TrimSpace(r.PathValue("id"))
		cleared, err := config.CatalogOverrides.ClearContext(r.Context(), tenant, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("catalog override removal could not be confirmed; reload and retry"))
			return
		}
		if config.ApplyMaterializedCertPinBypass != nil {
			config.ApplyMaterializedCertPinBypass(tenant)
		}
		writeCatalogContextResponse(w, r, "tenant", map[string]any{"entry_id": id, "cleared": cleared})
	}))

}

// The optional envelope preserves existing API clients while allowing the Console
// to verify both its authenticated context and the scope of the operation. Feed
// changes remain deployment-wide and keep the operator authorization above.
func writeCatalogContextResponse(w http.ResponseWriter, r *http.Request, scope string, data any) {
	if r.URL.Query().Get("scoped") == "1" {
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": adminTenantIDFromRequest(r), "scope": scope, "data": data})
		return
	}
	writeJSON(w, http.StatusOK, data)
}

// Refresh shared override authority before presenting either configured or live
// selections. The existing callback rebuilds all tenant inspection patterns.
func refreshCatalogOverrides(w http.ResponseWriter, config serverConfig) bool {
	if !refreshInspectionPosture(w, config) {
		return false
	}
	if config.CatalogOverrides == nil {
		return true
	}
	changed, err := config.CatalogOverrides.RefreshShared()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Catalog overrides cannot be refreshed from storage."))
		return false
	}
	if changed && config.ApplyMaterializedCertPinBypass != nil {
		config.ApplyMaterializedCertPinBypass("")
	}
	return true
}
