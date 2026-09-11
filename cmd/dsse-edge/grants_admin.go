package main

import (
	"fmt"
	"net/http"
	"strings"

	grantstore "github.com/lantern-networks/dsse-core/grantstore"
)

// registerGrantsAdmin wires the federated-auth GRANTS admin API (proprietary control plane): list the grants
// minted by the clientless broker and REVOKE one (continuous revocation — a revoked grant denies the next
// flow). Model + storage live in dsse-core (grantstore). See docs/idp_federated_authentication_design.md.
//
// Tenant isolation (review finding #2): both endpoints resolve the CALLER's tenant from the request
// (adminTenantIDFromRequest) and never a startup-fixed value — LIST returns only the caller's grants, and REVOKE
// verifies the target grant belongs to the caller's tenant before revoking (otherwise a grant id alone would be a
// cross-tenant IDOR: any admin could revoke any tenant's grant). Fail closed when no tenant resolves.
func registerGrantsAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *grantstore.Store, tenantID string) {
	mux.HandleFunc("GET /admin/grants", adminEndpoint("admin.grants.read", func(w http.ResponseWriter, r *http.Request) {
		callerTenant := strings.TrimSpace(adminTenantIDFromRequest(r))
		if callerTenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": store.List(callerTenant)})
	}))
	mux.HandleFunc("POST /admin/grants/{id}/revoke", adminEndpoint("admin.grants.write", func(w http.ResponseWriter, r *http.Request) {
		callerTenant := strings.TrimSpace(adminTenantIDFromRequest(r))
		if callerTenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		id := r.PathValue("id")
		// A grant in another tenant is treated as NOT FOUND (don't leak its existence or let this admin revoke it).
		if g, ok := store.Get(id); !ok || !strings.EqualFold(strings.TrimSpace(g.TenantID), callerTenant) {
			writeError(w, http.StatusNotFound, fmt.Errorf("grant not found"))
			return
		}
		if !store.Revoke(id) {
			writeError(w, http.StatusNotFound, fmt.Errorf("grant not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "grant_id": id})
	}))
}
