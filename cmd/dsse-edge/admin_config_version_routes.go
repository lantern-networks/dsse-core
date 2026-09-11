package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
)

// Generic S6 config-version API (record + read versions for any admin resource).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerConfigVersionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator) {
	mux.HandleFunc("POST /admin/config-versions", adminEndpoint("admin.config.write", func(w http.ResponseWriter, r *http.Request) {
		if config.ConfigVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		var req configVersionRecordRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil || strings.TrimSpace(req.ResourceType) == "" || strings.TrimSpace(req.ResourceID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("resource_type and resource_id are required"))
			return
		}
		actor := strings.TrimSpace(req.Actor)
		if actor == "" {
			if identity, ok := adminIdentityFromRequest(r); ok {
				actor = identity.PrincipalID
			}
		}
		v, err := config.ConfigVersions.Record(r.Context(), adminTenantIDFromRequest(r), req.ResourceType, req.ResourceID, req.Action, actor, req.Note, req.Payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}))
	mux.HandleFunc("GET /admin/config-versions/{resource_type}/{resource_id}", adminEndpoint("admin.config.read", func(w http.ResponseWriter, r *http.Request) {
		if config.ConfigVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versions, err := config.ConfigVersions.List(r.Context(), adminTenantIDFromRequest(r), r.PathValue("resource_type"), r.PathValue("resource_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}))
	mux.HandleFunc("GET /admin/config-versions/{resource_type}/{resource_id}/{version_no}", adminEndpoint("admin.config.read", func(w http.ResponseWriter, r *http.Request) {
		if config.ConfigVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versionNo, perr := strconv.ParseInt(r.PathValue("version_no"), 10, 64)
		if perr != nil || versionNo <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid version_no"))
			return
		}
		v, ok, err := config.ConfigVersions.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("resource_type"), r.PathValue("resource_id"), versionNo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("version not found"))
			return
		}
		writeJSON(w, http.StatusOK, v)
	}))

	// (T) transport: the agent fetches the signing public key to PIN (so it can verify the signed agent-policy).
	// Pinning over the mTLS transport at deploy time is the trusted-channel establishment; the public key is
	// not secret. key_id lets the NE pick the right key.
}
