package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
)

// registerAssetCatalogAdmin wires the endpoint/group/service catalog admin API on the product edge. The
// catalog model + storage live in dsse-core (so audit logs reference named entities); these handlers reuse
// the admin.endpoints.* RBAC scope (endpoints/groups/services are the endpoint catalog). The Admin Console
// reads/writes through these.
// ★ THE CONTROL PLANE IS THE AUTHORITY FOR ASSETS (operator decision, 2026-08-11).
//
// "CP authority is absolute; Edges come and go." An Edge is a replaceable instance, so anything an operator
// authored on one is lost the moment that instance is replaced — and until this change the asset catalog was
// exactly that: endpoints, groups and services written to whichever Edge the console happened to reach, held
// nowhere else.
//
// These writes are therefore refused on a config-pulling Edge and authored on the control plane, which
// distributes them in the config bundle. That also makes deletion meaningful: the bundle can now carry the
// absence of an asset, because absence finally means "the authority does not have it" instead of "this
// instance never heard of it".
//
// ★ THE CUTOVER NEEDS A MIGRATION AND HAS NO SAFE DEFAULT. Turning reconciliation on while an Edge still holds
// assets the CP never received deletes them on the first pull. That is not hypothetical: it removed 47 on this
// lab's Edge (docs/2026-08-11_asset_reconciliation_deleted_47_operator_assets.md). Copy them up first —
// ops/migrate_edge_assets_to_cp.sh.
func registerAssetCatalogAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *assetcatalog.Store, syncEnrolled func(), configSourceURL string, onChanged func(), audit func(*http.Request, string, string, string, string, any)) {
	var mutationMu sync.Mutex
	record := func(r *http.Request, kind, id, operation string, value any, err error, found bool) {
		result := "saved"
		if !found {
			result = "not_found"
		}
		if err != nil {
			result = "rejected"
			if errors.Is(err, assetcatalog.ErrPersistence) {
				result = "persistence_unconfirmed"
			}
		}
		if audit != nil {
			audit(r, kind, id, operation, result, value)
		}
	}
	writeFailure := func(w http.ResponseWriter, err error) {
		if errors.Is(err, assetcatalog.ErrPersistence) {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("Saving the catalog was not confirmed. The previous live catalog remains active. Restore storage, reload and retry."))
			return
		}
		writeError(w, http.StatusBadRequest, err)
	}
	changed := func() {
		if onChanged != nil {
			onChanged()
		}
	}

	// syncNow refreshes the enrolled (steered) endpoints from the live inventory before a read, so the
	// catalog reflects devices enrolled after startup without a restart. No-op when not wired (OSS/tests).
	syncNow := func() {
		if syncEnrolled != nil {
			syncEnrolled()
		}
	}
	mux.HandleFunc("GET /admin/assets/endpoints", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		syncNow()
		writeJSON(w, http.StatusOK, store.ListEndpoints(adminTenantIDFromRequest(r)))
	}))
	mux.HandleFunc("POST /admin/assets/endpoints", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "endpoint assets") {
			return
		}
		var e assetcatalog.Endpoint
		if err := decodeLimitedJSONBody(w, r, &e, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode endpoint: %w", err))
			return
		}
		// ★ The organization comes from the caller, and naming another is ANSWERED rather than silently
		// replaced (2026-08-18): an operator authoring a endpoint asset FOR a customer used to get 200 with the
		// record filed under the operator's own organization, where that customer never sees it.
		tenantForWrite, terr := adminTenantForWrite(r, e.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		e.TenantID = tenantForWrite
		mutationMu.Lock()
		defer mutationMu.Unlock()
		stored, err := store.UpsertEndpoint(e)
		item := stored
		if err != nil {
			item = e
		}
		record(r, "endpoint", item.ID, "upsert", item, err, true)
		if err != nil {
			writeFailure(w, err)
			return
		}
		changed()
		writeJSON(w, http.StatusOK, stored)
	}))
	mux.HandleFunc("DELETE /admin/assets/endpoints/{id}", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		// Deleting locally would be undone by the next bundle anyway — and worse, it would look like it worked.
		if configWriteRejectedWhenSourced(w, configSourceURL, "endpoint assets") {
			return
		}
		mutationMu.Lock()
		defer mutationMu.Unlock()
		ok, err := store.DeleteEndpoint(adminTenantIDFromRequest(r), r.PathValue("id"))
		record(r, "endpoint", r.PathValue("id"), "delete", nil, err, ok)
		if err != nil {
			writeFailure(w, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("endpoint not found"))
			return
		}
		changed()
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": r.PathValue("id")})
	}))

	mux.HandleFunc("GET /admin/assets/groups", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.ListGroups(adminTenantIDFromRequest(r)))
	}))
	mux.HandleFunc("POST /admin/assets/groups", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "endpoint group assets") {
			return
		}
		var g assetcatalog.Group
		if err := decodeLimitedJSONBody(w, r, &g, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode group: %w", err))
			return
		}
		// ★ The organization comes from the caller, and naming another is ANSWERED rather than silently
		// replaced (2026-08-18): an operator authoring a asset group FOR a customer used to get 200 with the
		// record filed under the operator's own organization, where that customer never sees it.
		tenantForWrite, terr := adminTenantForWrite(r, g.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		g.TenantID = tenantForWrite
		mutationMu.Lock()
		defer mutationMu.Unlock()
		stored, err := store.UpsertGroup(g)
		item := stored
		if err != nil {
			item = g
		}
		record(r, "group", item.ID, "upsert", item, err, true)
		if err != nil {
			writeFailure(w, err)
			return
		}
		changed()
		writeJSON(w, http.StatusOK, stored)
	}))
	mux.HandleFunc("GET /admin/assets/groups/{group_id}/members", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		syncNow()
		writeJSON(w, http.StatusOK, store.ResolveGroupMembers(adminTenantIDFromRequest(r), r.PathValue("group_id")))
	}))
	mux.HandleFunc("DELETE /admin/assets/groups/{id}", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		// Deleting locally would be undone by the next bundle anyway — and worse, it would look like it worked.
		if configWriteRejectedWhenSourced(w, configSourceURL, "endpoint group assets") {
			return
		}
		mutationMu.Lock()
		defer mutationMu.Unlock()
		ok, err := store.DeleteGroup(adminTenantIDFromRequest(r), r.PathValue("id"))
		record(r, "group", r.PathValue("id"), "delete", nil, err, ok)
		if err != nil {
			writeFailure(w, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("group not found"))
			return
		}
		changed()
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": r.PathValue("id")})
	}))

	mux.HandleFunc("GET /admin/assets/services", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.ListServices(adminTenantIDFromRequest(r)))
	}))
	mux.HandleFunc("POST /admin/assets/services", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "service assets") {
			return
		}
		var svc assetcatalog.Service
		if err := decodeLimitedJSONBody(w, r, &svc, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode service: %w", err))
			return
		}
		// ★ The organization comes from the caller, and naming another is ANSWERED rather than silently
		// replaced (2026-08-18): an operator authoring a asset service FOR a customer used to get 200 with the
		// record filed under the operator's own organization, where that customer never sees it.
		tenantForWrite, terr := adminTenantForWrite(r, svc.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		svc.TenantID = tenantForWrite
		mutationMu.Lock()
		defer mutationMu.Unlock()
		stored, err := store.UpsertService(svc)
		item := stored
		if err != nil {
			item = svc
		}
		record(r, "service", item.ID, "upsert", item, err, true)
		if err != nil {
			writeFailure(w, err)
			return
		}
		changed()
		writeJSON(w, http.StatusOK, stored)
	}))
	mux.HandleFunc("DELETE /admin/assets/services/{id}", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		// Deleting locally would be undone by the next bundle anyway — and worse, it would look like it worked.
		if configWriteRejectedWhenSourced(w, configSourceURL, "service assets") {
			return
		}
		mutationMu.Lock()
		defer mutationMu.Unlock()
		ok, err := store.DeleteService(adminTenantIDFromRequest(r), r.PathValue("id"))
		record(r, "service", r.PathValue("id"), "delete", nil, err, ok)
		if err != nil {
			writeFailure(w, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("service not found"))
			return
		}
		changed()
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": r.PathValue("id")})
	}))
}

// normalizeAssetPlatform maps an endpoint-inventory OS string ("macOS", "Windows", …) to the catalog's
// platform value ("macos" / "windows"), used when auto-populating endpoints from the enrolled inventory.
func normalizeAssetPlatform(os string) string {
	l := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.Contains(l, "mac"):
		return "macos"
	case strings.Contains(l, "win"):
		return "windows"
	default:
		return ""
	}
}
