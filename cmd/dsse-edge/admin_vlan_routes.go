package main

// VLAN Boundary Enforcement admin routes (Named Networks / Subnet objects +
// inter-VLAN boundary policies + the agentless-firewall export), moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Parameter names match the
// constructor's locals so the handler bodies are untouched.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

func registerVLANRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, vlanBoundary *vlan.Store, configSourceURL string) {
	mux.HandleFunc("POST /admin/vlan-objects", adminEndpoint("admin.vlan.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "VLAN objects") {
			return
		}
		var o model.VLANObject
		if err := decodeLimitedJSONBody(w, r, &o, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// The organization comes from the CALLER, never from the body: a body-supplied tenant_id let a
		// customer file an object under another organization's name. An operator may still author on behalf of
		// an organization, which is what X-Operate-Tenant already means and adminTenantIDFromRequest resolves.
		tenantForWrite, terr := adminTenantForWrite(r, o.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		o.TenantID = tenantForWrite
		if vlanLegacyWriteRefused(w, r, vlanBoundary, o.ID, false) {
			return
		}
		saved, err := vlanBoundary.UpsertObjectContext(r.Context(), o, vlanOwnerForWrite(r, o.TenantID))
		if err != nil {
			writeVLANMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	}))
	mux.HandleFunc("GET /admin/vlan-objects", adminEndpoint("admin.vlan.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshVLANStore(w, vlanBoundary) {
			return
		}
		callerTenant, isOperator := adminVLANCallerTenant(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"objects": vlanObjectsVisibleTo(vlanBoundary.ListObjects(), callerTenant, isOperator),
		})
	}))
	mux.HandleFunc("DELETE /admin/vlan-objects/{object_id}", adminEndpoint("admin.vlan.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "VLAN objects") {
			return
		}
		id := r.PathValue("object_id")
		if vlanLegacyWriteRefused(w, r, vlanBoundary, id, false) {
			return
		}
		// Authorize against the latest row in the same transaction as deletion.
		deleted, err := vlanBoundary.DeleteObjectContext(r.Context(), id, vlanOwnerForWrite(r, ""))
		if err != nil {
			writeVLANMutationError(w, err)
			return
		}
		if !deleted {
			writeError(w, http.StatusNotFound, fmt.Errorf("vlan object %q is absent", id))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	}))
	mux.HandleFunc("POST /admin/vlan-boundary-policies", adminEndpoint("admin.vlan.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "VLAN boundary policies") {
			return
		}
		var p model.VLANBoundaryPolicy
		if err := decodeLimitedJSONBody(w, r, &p, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		tenantForWrite, terr := adminTenantForWrite(r, p.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		p.TenantID = tenantForWrite
		if vlanLegacyWriteRefused(w, r, vlanBoundary, p.ID, true) {
			return
		}
		saved, err := vlanBoundary.UpsertPolicyContext(r.Context(), p, vlanOwnerForWrite(r, p.TenantID))
		if err != nil {
			writeVLANMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	}))
	mux.HandleFunc("GET /admin/vlan-boundary-policies", adminEndpoint("admin.vlan.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshVLANStore(w, vlanBoundary) {
			return
		}
		callerTenant, isOperator := adminVLANCallerTenant(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"policies": vlanPoliciesVisibleTo(vlanBoundary.ListPolicies(), callerTenant, isOperator),
		})
	}))
	mux.HandleFunc("GET /admin/vlan-boundary-policies/export", adminEndpoint("admin.vlan.read", func(w http.ResponseWriter, r *http.Request) {
		// The export is what somebody pastes into a firewall. Built from the caller's own definitions only —
		// an export carrying another organization's subnets is that organization's network map leaving with it.
		if !refreshVLANStore(w, vlanBoundary) {
			return
		}
		callerTenant, isOperator := adminVLANCallerTenant(r)
		export := vlan.BuildBoundaryExport(
			vlanObjectsVisibleTo(vlanBoundary.ListObjects(), callerTenant, isOperator),
			vlanPoliciesVisibleTo(vlanBoundary.ListPolicies(), callerTenant, isOperator),
			time.Now().UTC().Format(time.RFC3339))
		writeJSON(w, http.StatusOK, export)
	}))
}

func writeVLANMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, vlan.ErrNotFound) {
		writeError(w, http.StatusNotFound, vlan.ErrNotFound)
		return
	}
	if errors.Is(err, vlan.ErrPersistence) {
		writeError(w, http.StatusServiceUnavailable, errors.New("The network change could not be confirmed in storage. Reload before retrying."))
		return
	}
	writeError(w, http.StatusBadRequest, err)
}

// vlanLegacyWriteRefused answers a customer's change to a definition that has no
// organization with what is true: it exists (the same caller sees it listed),
// and only the operator may change it. The store's authorization answered
// ErrNotFound, so the Console said "absent" about a row it had just shown.
// There is no oracle concern: unowned definitions are visible to every tenant.
// The store still re-checks ownership inside the transaction.
func vlanLegacyWriteRefused(w http.ResponseWriter, r *http.Request, store *vlan.Store, id string, policy bool) bool {
	if _, operator := adminVLANCallerTenant(r); operator || strings.TrimSpace(id) == "" {
		return false
	}
	if !refreshVLANStore(w, store) {
		return true
	}
	unowned := false
	if policy {
		for _, p := range store.ListPolicies() {
			if p.ID == id && strings.TrimSpace(p.TenantID) == "" {
				unowned = true
			}
		}
	} else if o, ok := store.GetObject(id); ok && strings.TrimSpace(o.TenantID) == "" {
		unowned = true
	}
	if unowned {
		writeError(w, http.StatusForbidden, errors.New("This definition has no organization: it predates per-organization Networks and only the deployment operator can change or remove it."))
		return true
	}
	return false
}

// Reading legacy unowned definitions remains compatible, but modifying them
// requires the operator. Existing ownership cannot be reassigned by an upsert.
func vlanOwnerForWrite(r *http.Request, targetTenant string) func(string) bool {
	tenant, operator := adminVLANCallerTenant(r)
	return func(owner string) bool {
		owner = strings.TrimSpace(owner)
		if !operator && (owner == "" || !strings.EqualFold(owner, tenant)) {
			return false
		}
		return targetTenant == "" || owner == "" || strings.EqualFold(owner, targetTenant)
	}
}

func refreshVLANStore(w http.ResponseWriter, store *vlan.Store) bool {
	if err := store.RefreshShared(); err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Network configuration cannot be refreshed from storage."))
		return false
	}
	return true
}
