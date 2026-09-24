package main

import (
	"errors"
	"fmt"
	"net/http"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
)

// registerIdPConnectionsAdmin wires the per-tenant END-USER IdP registry admin API (proprietary control
// plane): the trusted IdP connections a policy's federated re-authentication redirects to, plus the tenant
// default. CRUD + set-default; the RP client secret is redacted on read. Model + storage live in dsse-core
// (idpregistry); this is the product edge's admin surface over it. See
// docs/idp_federated_authentication_design.md.
func registerIdPConnectionsAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *idpregistry.Store, configSourceURL string, record func(*http.Request, string, string, string)) {
	mux.HandleFunc("GET /admin/idp-connections", adminEndpoint("admin.idp.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		conns, defaultID, err := store.TenantSnapshot(tenant)
		if err != nil {
			writeError(w, 500, err)
			return
		}
		redacted := make([]idpregistry.Connection, 0, len(conns))
		for _, c := range conns {
			redacted = append(redacted, c.Redacted())
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"connections":    redacted,
			"default_idp_id": defaultID,
		})
	}))

	mux.HandleFunc("POST /admin/idp-connections", adminEndpoint("admin.idp.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ WHO MAY SIGN IN IS THE CONTROL PLANE'S (2026-08-24, measured). Asked of both nodes with one
		// administrator session, this Edge answered FOUR connections and the control plane answered zero — the
		// authority had never heard of any of them. An identity provider added here decides who can sign in to
		// one node, which is not a thing a deployment can mean.
		if configWriteRejectedWhenSourced(w, configSourceURL, "an identity-provider connection") {
			return
		}
		var conn idpregistry.Connection
		if err := decodeLimitedJSONBody(w, r, &conn, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode idp connection: %w", err))
			return
		}
		// ★ THE ORGANIZATION COMES FROM THE CALLER, AND NAMING ANOTHER IS ANSWERED (2026-08-18). This assigned
		// the caller's tenant over whatever the body said, silently: an operator registering an IdP FOR a
		// customer got 200 and the connection filed under the OPERATOR's own organization, where the customer
		// will never see it and nobody is told. adminTenantForWrite is the shared answer — an operator may name
		// another organization, a customer naming one is refused rather than redirected.
		tenantForWrite, terr := adminTenantForWrite(r, conn.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		conn.TenantID = tenantForWrite
		stored, err := store.UpsertContext(r.Context(), conn)
		if err != nil {
			writeError(w, statusForIdPStoreError(err), err)
			return
		}
		record(r, stored.TenantID, stored.IdPID, "upserted")
		writeJSON(w, http.StatusOK, stored.Redacted())
	}))

	mux.HandleFunc("DELETE /admin/idp-connections/{id}", adminEndpoint("admin.idp.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ WHO MAY SIGN IN IS THE CONTROL PLANE'S (2026-08-24, measured). Asked of both nodes with one
		// administrator session, this Edge answered FOUR connections and the control plane answered zero — the
		// authority had never heard of any of them. An identity provider added here decides who can sign in to
		// one node, which is not a thing a deployment can mean.
		if configWriteRejectedWhenSourced(w, configSourceURL, "an identity-provider connection") {
			return
		}
		ok, err := store.DeleteContext(r.Context(), adminTenantIDFromRequest(r), r.PathValue("id"))
		if err != nil {
			writeError(w, statusForIdPStoreError(err), err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("idp connection not found"))
			return
		}
		record(r, adminTenantIDFromRequest(r), r.PathValue("id"), "deleted")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": r.PathValue("id")})
	}))

	mux.HandleFunc("POST /admin/idp-connections/{id}/default", adminEndpoint("admin.idp.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ WHO MAY SIGN IN IS THE CONTROL PLANE'S (2026-08-24, measured). Asked of both nodes with one
		// administrator session, this Edge answered FOUR connections and the control plane answered zero — the
		// authority had never heard of any of them. An identity provider added here decides who can sign in to
		// one node, which is not a thing a deployment can mean.
		if configWriteRejectedWhenSourced(w, configSourceURL, "an identity-provider connection") {
			return
		}
		if err := store.SetDefaultContext(r.Context(), adminTenantIDFromRequest(r), r.PathValue("id")); err != nil {
			writeError(w, statusForIdPStoreError(err), err)
			return
		}
		record(r, adminTenantIDFromRequest(r), r.PathValue("id"), "default_set")
		writeJSON(w, http.StatusOK, map[string]string{"status": "default_set", "id": r.PathValue("id")})
	}))

	// Non-interactive connection test (the Console "Test" button): probe the registered IdP's published signing
	// keys + OIDC discovery so an operator gets an OK/not-OK verdict right after registering, without driving a
	// full login. A safe, idempotent, side-effect-free READ — GET (so it uses the same auth path as the other
	// reads, with no mutating-method CSRF requirement). admin.idp.read.
	mux.HandleFunc("GET /admin/idp-connections/{id}/test", adminEndpoint("admin.idp.read", func(w http.ResponseWriter, r *http.Request) {
		rows, _, err := store.TenantSnapshot(adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, 500, err)
			return
		}
		var conn idpregistry.Connection
		ok := false
		for _, c := range rows {
			if c.IdPID == r.PathValue("id") {
				conn = c
				ok = true
				break
			}
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("idp connection not found"))
			return
		}
		writeJSON(w, http.StatusOK, testIdPConnection(conn))
	}))
}

func statusForIdPStoreError(err error) int {
	if errors.Is(err, idpregistry.ErrPersistence) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}
