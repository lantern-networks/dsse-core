package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/internalca"
)

// The authorities an organization vouches for when an Edge verifies one of ITS OWN private assets.
//
// Scoped to the caller's organization on every route. The list widens what one organization's flows will
// accept, so an administrator of one organization must never be able to read or write another's — a private
// asset's authority is also a statement about what that organization's devices can be sent to.
func registerInternalCARoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig) {
	store, _ := config.InternalCAs.(*internalca.Store)

	mux.HandleFunc("GET /admin/internal-cas", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("this deployment has no store for internal certificate authorities"))
			return
		}
		// ★ THE SAME RULE AS THE WRITE, AND IT WAS NOT (2026-09-01, found the moment an operator tried to undo
		// its own act). The write let an operator name a customer's organization; the read and the delete were
		// scoped to the caller's own. So an operator could add an authority for a customer and then neither see
		// it nor remove it — "no such authority in this organization", about a row it had just created. One
		// rule, in one place, for all three.
		tenant, tenantErr := adminTenantForWrite(r, r.URL.Query().Get("tenant_id"))
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"internal_cas": store.List(tenant, time.Now().UTC())})
	}))

	// ★★★ THE FLEET ANSWER, AND WHY IT IS A SEPARATE ROUTE. An Edge carries flows for MANY organizations, so
	// an Edge that pulled only "my organization's" list would refuse every other organization's private assets
	// while reporting itself healthy — the shape found eight times in one day: a question about somebody else
	// answered with an attribute of this node. Only the operator organization may read it, because it is every
	// customer's list at once.
	mux.HandleFunc("GET /admin/internal-cas/all", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("this deployment has no store for internal certificate authorities"))
			return
		}
		operator := operatorTenantConfigured()
		if operator != "" && strings.TrimSpace(adminTenantIDFromRequest(r)) != operator {
			writeError(w, http.StatusForbidden, fmt.Errorf("only the operator organization may read every organization's authorities"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"internal_cas": store.ListAll(time.Now().UTC())})
	}))

	mux.HandleFunc("POST /admin/internal-cas", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("this deployment has no store for internal certificate authorities"))
			return
		}
		// ★ AN ENFORCING EDGE MUST NOT ACCEPT THIS. The list travels in the config bundle from the control
		// plane, so a write taken here would survive exactly until the next ten-second pull and then be erased
		// with no trace — the Console would show the authority added, and the private asset would stop opening
		// again a moment later. Refusing with a 409 that names where to write is the difference between an
		// error somebody can act on and a silent loss.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "internal certificate authorities") {
			return
		}
		var body internalca.Authority
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// ★ WHOSE LIST THIS IS, DECIDED IN ONE PLACE. A customer naming another organization is REFUSED rather
		// than quietly redirected into their own, and an operator acting for a customer may name it — the
		// difference an earlier write got wrong by simply overwriting the body, so an operator registered an
		// IdP for a customer, got a 200, and it was filed under the operator with nothing said. This object
		// widens what a deployment will trust, so a silent redirect here is worse than most.
		tenant, tenantErr := adminTenantForWrite(r, body.TenantID)
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		body.TenantID = tenant
		if strings.TrimSpace(body.ID) == "" {
			body.ID = fmt.Sprintf("ica-%d", time.Now().UTC().UnixNano())
		}
		saved, err := store.Upsert(body, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	}))

	mux.HandleFunc("DELETE /admin/internal-cas/{id}", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("this deployment has no store for internal certificate authorities"))
			return
		}
		// ★ AN ENFORCING EDGE MUST NOT ACCEPT THIS. The list travels in the config bundle from the control
		// plane, so a write taken here would survive exactly until the next ten-second pull and then be erased
		// with no trace — the Console would show the authority added, and the private asset would stop opening
		// again a moment later. Refusing with a 409 that names where to write is the difference between an
		// error somebody can act on and a silent loss.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "internal certificate authorities") {
			return
		}
		tenant, tenantErr := adminTenantForWrite(r, r.URL.Query().Get("tenant_id"))
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		if !store.Delete(r.PathValue("id"), tenant, time.Now().UTC()) {
			writeError(w, http.StatusNotFound, fmt.Errorf("no such authority in this organization"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	}))
}
