package main

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
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
func registerGrantsAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *grantstore.Store, evaluator decision.Evaluator, writer *logs.Writer, outbox adminAuditOutboxDeadReader, rollout *authRolloutRuntime, configSourceURL string) {
	mux.HandleFunc("GET /admin/grants", adminEndpoint("admin.grants.read", func(w http.ResponseWriter, r *http.Request) {
		callerTenant := strings.TrimSpace(adminTenantIDFromRequest(r))
		if callerTenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		rows, err := store.ListChecked(callerTenant)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": rows})
	}))
	mux.HandleFunc("POST /admin/grants/{id}/revoke", adminEndpoint("admin.grants.write", func(w http.ResponseWriter, r *http.Request) {
		callerTenant := strings.TrimSpace(adminTenantIDFromRequest(r))
		if callerTenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		id := r.PathValue("id")
		if strings.TrimSpace(configSourceURL) != "" {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("send revocation to the control-plane authority; this Edge cannot confirm an authoritative revocation"))
			return
		}
		strong := rollout.featureEnabled(authrollout.RevocationReauthenticationFeature)
		var grant grantstore.Grant
		var found bool
		var err error
		if strong {
			grant, found, err = store.RequireReauthenticationForTenantContext(r.Context(), callerTenant, id, time.Now().UTC())
		} else {
			grant, found, err = store.RevokeForTenantContext(r.Context(), callerTenant, id)
		}
		if err != nil && !found {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("grant not found"))
			return
		}
		now := time.Now().UTC()
		nonAtomic := errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed)
		audit := adminAccessGrantRevocationAuditLog(r, grant, evaluator, now, err != nil && !nonAtomic)
		if nonAtomic {
			audit.Metadata["persistence"] = "saved_non_atomic"
		}
		scope := store.ReauthenticationScope(grant)
		if scope == "tenant" {
			audit.Metadata["reauthentication_scope"] = scope
		}
		_ = appendAdminAudit(r.Context(), writer, outbox, audit, now)
		if err != nil && !nonAtomic {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"status": "partial", "applied": true, "tenant_id": grant.TenantID, "grant_id": grant.GrantID, "audit_ref": accessGrantAuditReference(grant.GrantID), "persistence": "unconfirmed", "reauthenticate_after": grant.ReauthenticateAfter, "fresh_identity_required": grant.ReauthenticateAfter != "", "reauthentication_scope": scope,
				"error": "Access was revoked on this server, but persistence is unconfirmed. Restore storage and retry saving this revocation before restarting.",
			})
			return
		}
		result := map[string]any{"status": "revoked", "grant_id": grant.GrantID, "tenant_id": grant.TenantID, "audit_ref": accessGrantAuditReference(grant.GrantID), "reauthenticate_after": grant.ReauthenticateAfter, "fresh_identity_required": grant.ReauthenticateAfter != ""}
		result["reauthentication_scope"] = scope
		if scope == "tenant" {
			result["warning"] = "Revocation boundaries were consolidated for this tenant. Other approvals in this tenant may also require fresh identity verification."
		}
		if grant.ReauthenticateAfter == "" {
			result["warning"] = "Approval revoked. Fresh identity verification is not enforced until revocation reauthentication is activated on all authentication nodes."
		}
		if nonAtomic {
			result["persistence"] = "saved_non_atomic"
		}
		writeJSON(w, http.StatusOK, result)
	}))
}
