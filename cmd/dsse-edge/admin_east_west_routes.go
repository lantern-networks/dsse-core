package main

// East-west (lateral movement) admin routes — status, S1 observe-mode inventory,
// authenticate-mode challenges, ephemeral grants + revoke, rule writes, and the S6
// config-version history/rollback — moved verbatim out of newServerWithConfig (Phase 2
// route-registration split). Only mechanical change: config.CPVersions /
// config.EastWestObserveStore became the cpVersions / eastWestObserveStore parameters.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func registerEastWestRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, policyStore policy.RuntimeStore, eastWestAuthChallenges *eastwest.AuthChallengeStore, cpVersions *cpConfigVersionClient, eastWestObserveStore *eastwestobserve.Store, configSourceURL string) {
	mux.HandleFunc("GET /admin/east-west", adminEndpoint("admin.eastwest.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eastwest.AdminStatus(policyStore, adminTenantIDFromRequest(r)))
	}))
	// S1 (Observe): the lateral-flow inventory + convergence readiness. Read-only; recording happens on the
	// steer-mux decision path. Coverage is computed against the CURRENT east-west rules (so it never goes stale).
	mux.HandleFunc("GET /admin/east-west/observations", adminEndpoint("admin.eastwest.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		var obs []eastwestobserve.FlowObservation
		if eastWestObserveStore != nil {
			if err := eastWestObserveStore.RefreshShared(); err != nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("observation inventory unavailable"))
				return
			}
			obs = eastWestObserveStore.List(tenant)
		}
		var rules []decision.EastWestRule
		if rr, ok := policyStore.(interface {
			EffectiveEastWestRules(string) []decision.EastWestRule
		}); ok {
			rules = rr.EffectiveEastWestRules(tenant)
		}
		for i := range obs {
			req := model.DecisionRequest{Destination: obs[i].Destination, ServiceFamily: obs[i].ServiceFamily}
			if obs[i].Source != eastwestobserve.SourceAny {
				req.DeviceID = obs[i].Source
			}
			_, obs[i].Covered = decision.MatchedEastWestRule(rules, req)
		}
		conv := eastwestobserve.ConvergenceOf(obs, func(o eastwestobserve.FlowObservation) bool { return o.Covered })
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "admin_east_west_observations.v1",
			"tenant_id":             tenant,
			"observations":          obs,
			"convergence":           conv,
			"no_secret_attestation": true,
		})
	}))
	mux.HandleFunc("GET /admin/east-west/challenges", adminEndpoint("admin.eastwest.read", func(w http.ResponseWriter, r *http.Request) {
		challenges := eastWestAuthChallenges.ListPending(adminTenantIDFromRequest(r), time.Now())
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "admin_east_west_challenges.v1",
			"tenant_id":             adminTenantIDFromRequest(r),
			"pending_challenges":    challenges,
			"no_secret_attestation": true,
		})
	}))
	mux.HandleFunc("GET /admin/east-west/grants", adminEndpoint("admin.eastwest.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, eastwest.AdminGrants(policyStore, adminTenantIDFromRequest(r), time.Now()))
	}))
	mux.HandleFunc("POST /admin/east-west/grants", adminEndpoint("admin.eastwest.write", func(w http.ResponseWriter, r *http.Request) {
		var req eastwest.AdminGrantIssueRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		resp, err := eastwest.IssueGrantDirect(policyStore, adminTenantIDFromRequest(r), req, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}))
	mux.HandleFunc("POST /admin/east-west/grants/revoke", adminEndpoint("admin.eastwest.write", func(w http.ResponseWriter, r *http.Request) {
		var req eastwest.GrantRevokeRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		resp, err := eastwest.RevokeGrants(policyStore, adminTenantIDFromRequest(r), req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}))
	mux.HandleFunc("POST /admin/east-west", adminEndpoint("admin.eastwest.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "east-west authorization config") {
			return
		}
		var req eastwest.AdminUpdateRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		resp, err := eastwest.ApplyAdminUpdateContext(r.Context(), policyStore, adminTenantIDFromRequest(r), req)
		if err != nil {
			if errors.Is(err, policy.ErrPolicyPersistence) {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Connector access policy save could not be confirmed. Reload before retrying."))
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		shipConfigVersionToCP(r, cpVersions, configversion.ResourceEastWest, adminTenantIDFromRequest(r),
			configversion.ActionUpsert, "east-west rules update", req)
		writeJSON(w, http.StatusOK, resp)
	}))
	// S6: east-west history + rollback (Edge-side resource versioned via the control plane).
	mux.HandleFunc("GET /admin/east-west/versions", adminEndpoint("admin.eastwest.read", func(w http.ResponseWriter, r *http.Request) {
		if cpVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versions, err := cpVersions.List(r.Context(), configversion.ResourceEastWest, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}))
	mux.HandleFunc("POST /admin/east-west/rollback", adminEndpoint("admin.eastwest.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "east-west authorization config") {
			return
		}
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
		version, ok, err := cpVersions.Get(r.Context(), configversion.ResourceEastWest, adminTenantIDFromRequest(r), body.VersionNo)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("version %d not found", body.VersionNo))
			return
		}
		var req eastwest.AdminUpdateRequest
		if err := json.Unmarshal(version.Payload, &req); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("decode version payload: %w", err))
			return
		}
		resp, err := eastwest.ApplyAdminUpdateContext(r.Context(), policyStore, adminTenantIDFromRequest(r), req)
		if err != nil {
			if errors.Is(err, policy.ErrPolicyPersistence) {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Connector access policy save could not be confirmed. Reload before retrying."))
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		shipConfigVersionToCP(r, cpVersions, configversion.ResourceEastWest, adminTenantIDFromRequest(r),
			configversion.ActionRollback, fmt.Sprintf("rolled back to version %d", body.VersionNo), req)
		writeJSON(w, http.StatusOK, map[string]any{"rolled_back_to": body.VersionNo, "east_west": resp})
	}))
}
