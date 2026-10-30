package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

type upstreamTLSResponse struct {
	TenantID     string `json:"tenant_id"`
	Scope        string `json:"scope"`
	Mode         string `json:"mode"`
	Configurable bool   `json:"configurable"`
}

func upstreamTLSResponseFor(config serverConfig, store policy.RuntimeStore, r *http.Request, tenant string) upstreamTLSResponse {
	mode := policy.EffectiveUpstreamTLSMode(store.SnapshotTenantConfig(tenant).UpstreamTLSMode)
	identity, ok := adminIdentityFromRequest(r)
	writable := ok && adminPermissionAllowed(identity.Roles, "admin.policy.write") && adminScopeAllowed(identity, "admin.policy.write")
	if ok && !writable && adminScopeAllowed(identity, "admin.policy.write") {
		envelope := operatorDelegationForRequest(r.Context(), r, identity, config.TenantModelStore, time.Now())
		writable = envelope.Delegated && !envelope.Unavailable && (!envelope.NeedsElevation || envelope.Elevated)
	}
	durable, supported := store.(interface{ UpstreamTLSConfigurable() bool })
	return upstreamTLSResponse{TenantID: tenant, Scope: "tenant", Mode: mode, Configurable: writable && supported && durable.UpstreamTLSConfigurable() && strings.TrimSpace(config.ConfigSourceURL) == "" && (cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader())}
}

func upstreamTLSTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, deployment := adminAnswerScope(r)
	if tenant == "" || deployment {
		writeError(w, http.StatusBadRequest, fmt.Errorf("select an organization before configuring upstream TLS"))
		return "", false
	}
	// Tenant selection is authenticated request context, never a query/body override.
	if requested := strings.TrimSpace(r.URL.Query().Get("tenant_id")); requested != "" && requested != tenant {
		writeError(w, http.StatusForbidden, fmt.Errorf("upstream TLS is scoped to the selected organization"))
		return "", false
	}
	return tenant, true
}

func registerUpstreamTLSRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, store policy.RuntimeStore) {
	mux.HandleFunc("GET /admin/upstream-tls", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := upstreamTLSTenant(w, r)
		if !ok {
			return
		}
		if err := refreshManagedTenantRestrictions(store); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("upstream TLS settings are unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, upstreamTLSResponseFor(config, store, r, tenant))
	}))
	mux.HandleFunc("POST /admin/upstream-tls", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "upstream TLS settings") {
			return
		}
		tenant, ok := upstreamTLSTenant(w, r)
		if !ok {
			return
		}
		var body struct {
			Mode string `json:"mode"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEdgeRuntimeJSONBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid upstream TLS settings"))
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			writeError(w, http.StatusBadRequest, fmt.Errorf("expected one upstream TLS settings object"))
			return
		}
		if body.Mode == "" || policy.ValidateUpstreamTLSMode(body.Mode) != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("mode must be strict or browser_compatible"))
			return
		}
		author, ok := store.(*policy.Store)
		if !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("upstream TLS authoring is unavailable"))
			return
		}
		err := author.SetUpstreamTLSModeContext(r.Context(), tenant, body.Mode)
		now := time.Now().UTC()
		result := "saved"
		if err != nil {
			result = "persistence_unconfirmed"
		}
		audit := model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: tenant, ActorUserID: auditActorPrincipal(r), EventType: "admin_upstream_tls_updated", TargetType: stringPtr("upstream_tls"), TargetID: stringPtr("upstream_tls"), Action: stringPtr("update"), Result: stringPtr(result), Timestamp: now.Format(time.RFC3339), EdgeRegionID: &config.Evaluator.EdgeRegionID, EdgeClusterID: &config.Evaluator.EdgeClusterID, Metadata: map[string]any{"mode": body.Mode, "scope": "tenant"}}
		_ = appendAdminAudit(r.Context(), config.Writer, config.AdminAuditOutbox, audit, now)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, policy.ErrPolicyPersistence) {
				status = http.StatusServiceUnavailable
			}
			writeError(w, status, fmt.Errorf("upstream TLS settings were not confirmed saved"))
			return
		}
		writeJSON(w, http.StatusOK, upstreamTLSResponseFor(config, store, r, tenant))
	}))
}
