package main

import (
	"fmt"
	"net/http"
)

// Organization-domain admin routes (the tenant's own-domain set for identity scoping).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerOrganizationDomainRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, organizationDomains *organizationDomainsStore) {
	mux.HandleFunc("GET /admin/organization-domains", adminEndpoint("admin.config.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"domains": organizationDomains.Domains(adminTenantIDFromRequest(r))})
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
		saved := organizationDomains.SetDomains(tenant, body.Domains)
		logInfof("organization_domains_applied_by_admin tenant=%s domains=%d", tenant, len(saved))
		writeJSON(w, http.StatusOK, map[string]any{"domains": saved})
	}))

}
