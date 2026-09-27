package main

import (
	"fmt"
	"net/http"
)

// Organization-domain admin routes (the tenant's own-domain set for identity scoping).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerOrganizationDomainRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, organizationDomains *organizationDomainsStore) {
	mux.HandleFunc("GET /admin/organization-domains", adminEndpoint("admin.config.read", func(w http.ResponseWriter, r *http.Request) {
		domains, err := organizationDomains.DomainsChecked(adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, 500, fmt.Errorf("could not load organization domains"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
	}))
	mux.HandleFunc("PUT /admin/organization-domains", adminEndpoint("admin.config.write", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Domains []string `json:"domains"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode organization domains: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		saved, err := organizationDomains.SetDomainsContext(r.Context(), tenant, body.Domains)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save organization domains"))
			return
		}
		logInfof("organization_domains_applied_by_admin tenant=%s domains=%d", tenant, len(saved))
		writeJSON(w, http.StatusOK, map[string]any{"domains": saved})
	}))

}
