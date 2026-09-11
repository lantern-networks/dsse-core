package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

// Admin-managed steer-exclusion routes (CRUD, V-1 versions/rollback, and the observed
// reverse-telemetry view). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerSteerExclusionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer) {
	mux.HandleFunc("GET /admin/steer-exclusions", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		if config.SteerExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer exclusions are not enabled"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"steer_exclusions": config.SteerExclusions.List(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/steer-exclusions", adminEndpoint("admin.steering.write", func(w http.ResponseWriter, r *http.Request) {
		// This Edge PULLS its exclusions from a control plane, so a write accepted here lives until the next
		// poll and is then erased with no trace — the Console showed the rule created, and it was gone fifteen
		// seconds later. Refusing with a 409 that names where to write instead is the difference between a
		// visible error and a silent loss (docs/config_persistence_and_rollback.md P-3).
		if configWriteRejectedWhenSourced(w, config.SteerExclusionSourceURL, "steer exclusions") {
			return
		}
		if config.SteerExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer exclusions are not enabled"))
			return
		}
		var p steerexclusion.Policy
		if err := decodeLimitedJSONBody(w, r, &p, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// The organization is the caller's, never the body's: a customer filed an exclusion under another
		// organization and it landed in that organization's list, exempting an app for their whole fleet.
		tenantForWrite, terr := adminTenantForWrite(r, p.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		p.TenantID = tenantForWrite
		saved, err := config.SteerExclusions.Upsert(p, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		recordConfigVersion(r, config.ConfigVersions, configversion.ResourceSteerExclusion, saved.ID, configversion.ActionUpsert, saved.Note, saved)
		writeJSON(w, http.StatusOK, saved)
	}))
	mux.HandleFunc("DELETE /admin/steer-exclusions/{id}", adminEndpoint("admin.steering.write", func(w http.ResponseWriter, r *http.Request) {
		// This Edge PULLS its exclusions from a control plane, so a write accepted here lives until the next
		// poll and is then erased with no trace — the Console showed the rule created, and it was gone fifteen
		// seconds later. Refusing with a 409 that names where to write instead is the difference between a
		// visible error and a silent loss (docs/config_persistence_and_rollback.md P-3).
		if configWriteRejectedWhenSourced(w, config.SteerExclusionSourceURL, "steer exclusions") {
			return
		}
		if config.SteerExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer exclusions are not enabled"))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		id := r.PathValue("id")
		before, hadBefore := config.SteerExclusions.Get(id, tenantID) // snapshot for the delete version (so a rollback can restore it)
		if !config.SteerExclusions.Delete(id, tenantID, time.Now()) {
			writeError(w, http.StatusNotFound, fmt.Errorf("steer exclusion %s is absent", id))
			return
		}
		if hadBefore {
			recordConfigVersion(r, config.ConfigVersions, configversion.ResourceSteerExclusion, id, configversion.ActionDelete, "deleted", before)
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
	}))
	// Config history + rollback (V-1): list every recorded version of a steer exclusion, and roll the
	// resource back to a prior version (which re-applies that snapshot as a NEW version — auditable, reversible).
	mux.HandleFunc("GET /admin/steer-exclusions/{id}/versions", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		if config.ConfigVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("config versioning is not enabled"))
			return
		}
		versions, err := config.ConfigVersions.List(r.Context(), adminTenantIDFromRequest(r), configversion.ResourceSteerExclusion, r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	}))
	mux.HandleFunc("POST /admin/steer-exclusions/{id}/rollback", adminEndpoint("admin.steering.write", func(w http.ResponseWriter, r *http.Request) {
		// Same reason as the create/delete routes: a rollback applied here is erased by the next CP poll.
		if configWriteRejectedWhenSourced(w, config.SteerExclusionSourceURL, "steer exclusions") {
			return
		}
		if config.SteerExclusions == nil || config.ConfigVersions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer exclusions or config versioning is not enabled"))
			return
		}
		var body struct {
			VersionNo int64 `json:"version_no"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil || body.VersionNo <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("a positive version_no is required"))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		id := r.PathValue("id")
		version, ok, err := config.ConfigVersions.Get(r.Context(), tenantID, configversion.ResourceSteerExclusion, id, body.VersionNo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("version %d of steer exclusion %s not found", body.VersionNo, id))
			return
		}
		var snapshot steerexclusion.Policy
		if err := json.Unmarshal(version.Payload, &snapshot); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("decode version payload: %w", err))
			return
		}
		snapshot.TenantID = tenantID
		snapshot.ID = id
		saved, err := config.SteerExclusions.Upsert(snapshot, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		recordConfigVersion(r, config.ConfigVersions, configversion.ResourceSteerExclusion, id, configversion.ActionRollback,
			fmt.Sprintf("rolled back to version %d", body.VersionNo), saved)
		writeJSON(w, http.StatusOK, map[string]any{"rolled_back_to": body.VersionNo, "steer_exclusion": saved})
	}))

	// Effective-set visibility. "observed" is the
	// REVERSE-telemetry view: what each device reports it ACTUALLY excludes (its merged floor+scaffold+admin
	// set) — this is where a hardcoded self-exclusion finally becomes visible to an admin. "resolved"
	// is the forward preview: the admin-authored set the Edge WOULD serve a given device (layer 3 only), so an
	// admin can check a policy's reach before the device next polls. Both are read-only and tenant-scoped.
	mux.HandleFunc("GET /admin/steer-exclusions/observed", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		if config.ObservedExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer-exclusion telemetry is not enabled"))
			return
		}
		// Scale: filtered + paginated, never the whole fleet (docs/steer_exclusions_observed_telemetry_scale_design.md).
		q := r.URL.Query()
		limit := 50
		if v := strings.TrimSpace(q.Get("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if limit > 500 {
			limit = 500
		}
		offset := 0
		if cur := strings.TrimSpace(q.Get("cursor")); cur != "" {
			if dec, err := base64.RawURLEncoding.DecodeString(cur); err == nil {
				if n, err := strconv.Atoi(string(dec)); err == nil && n >= 0 {
					offset = n
				}
			}
		}
		res := config.ObservedExclusions.Query(adminTenantIDFromRequest(r), observedQueryFilter{
			Device:        strings.TrimSpace(q.Get("device")),
			Group:         strings.TrimSpace(q.Get("group")),
			App:           strings.TrimSpace(q.Get("app")),
			AnomalousOnly: q.Get("anomalous") == "true",
			Limit:         limit,
			Offset:        offset,
		})
		nextCursor := ""
		if next := res.Offset + len(res.Entries); next < res.Total {
			nextCursor = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(next)))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"observed":       res.Entries,
			"total_estimate": res.Total,
			"next_cursor":    nextCursor,
		})
	}))
}

// Observed-exclusion analytics (per-app rollup) and the resolved effective set.
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerSteerExclusionObservedRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, deviceStore deviceRuntimeStore) {
	mux.HandleFunc("GET /admin/steer-exclusions/observed/by-app", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		if config.ObservedExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer-exclusion telemetry is not enabled"))
			return
		}
		limit := 100
		if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if limit > 1000 {
			limit = 1000
		}
		res := config.ObservedExclusions.ByApp(adminTenantIDFromRequest(r), limit)
		writeJSON(w, http.StatusOK, map[string]any{"apps": res.Apps, "device_total": res.DeviceTotal})
	}))
	mux.HandleFunc("GET /admin/steer-exclusions/resolved", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		if config.SteerExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer exclusions are not enabled"))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		device := strings.TrimSpace(r.URL.Query().Get("device"))
		if device == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("a device query parameter is required"))
			return
		}
		group := ""
		if deviceStore != nil {
			if dev, ok, derr := deviceForTenant(deviceStore, tenantID, device); derr == nil && ok {
				if g, has := dev.Metadata["device_group"]; has {
					if gs, isStr := g.(string); isStr {
						group = strings.TrimSpace(gs)
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"device_identity":          device,
			"device_group":             group,
			"resolved_app_signing_ids": config.SteerExclusions.ResolveForDevice(tenantID, device, group),
		})
	}))

	// Generic config-version API (S6): the control plane records + serves versions for ANY admin resource,
	// so the zero-DB enforcing Edge can SHIP its admin changes (e.g. tenant-restriction) here for history +
	// rollback. Available only where the durable store is wired (the control plane).
}
