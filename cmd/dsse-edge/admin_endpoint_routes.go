package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	"github.com/lantern-networks/dsse-core/logs"
)

// Endpoint-inventory admin routes. // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerEndpointInventoryListRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, deviceStore deviceRuntimeStore, endpointInventoryStore endpointinventory.RuntimeStore) {
	mux.HandleFunc("GET /admin/endpoints", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		// Re-derive from the device store first: this list was a start-up snapshot, so it reported live
		// devices as days stale. See refreshAdminEndpointInventory.
		refreshAdminEndpointInventory(endpointInventoryStore, adminTenantIDFromRequest(r), deviceStore, time.Now())
		options := endpointinventory.ListOptions{
			Status:           strings.TrimSpace(r.URL.Query().Get("status")),
			DeviceTrustLevel: strings.TrimSpace(r.URL.Query().Get("device_trust_level")),
			Limit:            boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := endpointInventoryStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))

	// Endpoint/group/service catalog (the named subjects policy rules refer to; model + storage in
	// dsse-core so audit logs reference named entities). main supplies the stores (so the bypass rebuild
	// can see authored egress rules); tests/headless fall back to empty in-process stores. Here we
	// auto-populate steered endpoints from the enrolled inventory so they appear without manual entry, and
	// register the admin APIs (/admin/assets/*).
}

// Endpoint detail + upsert. Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerEndpointInventoryDetailRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, deviceStore deviceRuntimeStore, endpointInventoryStore endpointinventory.RuntimeStore) {
	mux.HandleFunc("GET /admin/endpoints/{endpoint_id}", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		// Same refresh as the list route — a detail view that disagreed with the list would be worse than both.
		refreshAdminEndpointInventory(endpointInventoryStore, adminTenantIDFromRequest(r), deviceStore, time.Now())
		endpoint, found, err := endpointInventoryStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("endpoint_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("endpoint %s is absent", r.PathValue("endpoint_id")))
			return
		}
		writeJSON(w, http.StatusOK, endpoint)
	}))
	mux.HandleFunc("POST /admin/endpoints", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		var endpoint endpointinventory.Entry
		if err := decodeLimitedJSONBody(w, r, &endpoint, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode endpoint inventory entry: %w", err))
			return
		}
		now := time.Now()
		upserted, err := endpointInventoryStore.Upsert(r.Context(), endpoint, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminEndpointInventoryAuditLog(upserted, evaluator, now), now)
		writeJSON(w, http.StatusOK, upserted)
	}))
}
