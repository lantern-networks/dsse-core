package main

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"strings"
	"time"

	grantstore "github.com/lantern-networks/dsse-core/grantstore"
)

// registerGrantsAdmin wires the federated-auth federated access-grant admin API: list the grants
// minted by the clientless broker and REVOKE one (continuous revocation — a revoked grant denies the next
// flow). Model + storage live in dsse-core (grantstore). See docs/idp_federated_authentication_design.md.
//
// Tenant isolation (review finding #2): both endpoints resolve the CALLER's tenant from the request
// (adminTenantIDFromRequest) and never a startup-fixed value — LIST returns only the caller's grants, and REVOKE
// verifies the target grant belongs to the caller's tenant before revoking (otherwise a grant id alone would be a
// cross-tenant IDOR: any admin could revoke any tenant's grant). Fail closed when no tenant resolves.
func registerGrantsAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *grantstore.Store, evaluator decision.Evaluator, writer *logs.Writer, outbox adminAuditOutboxDeadReader) {
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
		grant, found, err := store.RevokeForTenant(callerTenant, id)
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("grant not found"))
			return
		}
		now := time.Now().UTC()
		audit := adminAccessGrantRevocationAuditLog(r, grant, evaluator, now, err != nil)
		_ = appendAdminAudit(r.Context(), writer, outbox, audit, now)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"status": "partial", "applied": true, "tenant_id": grant.TenantID, "grant_id": grant.GrantID, "audit_ref": accessGrantAuditReference(grant.GrantID), "persistence": "unconfirmed",
				"error": "Access was revoked on this server, but persistence is unconfirmed. Restore storage and retry saving this revocation before restarting.",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "grant_id": grant.GrantID, "tenant_id": grant.TenantID, "audit_ref": accessGrantAuditReference(grant.GrantID)})
	}))
}
