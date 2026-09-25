package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
	"github.com/lantern-networks/dsse-core/vlan"
)

// Connector admin routes (CP-configured routes, list/detail, runtime-secret rotate,
// rename, delete) and the site-first Connector UX (sites CRUD, site networks,
// enrollment command). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerConnectorSiteAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, registry connectorRegistryStore, tunnelManager *tunnel.Manager, siteStore adminSiteStore, vlanBoundary *vlan.Store, domainEventOutbox domainEventOutboxWriter, adminAuditOutbox adminAuditOutboxDeadReader, applicationCatalogStore appcatalog.RuntimeStore, tenantModelStore adminTenantModelRuntimeStore, configSourceURL string, connectorTunnelStatus func(string) *bool, connectorDeclaredRoutes func(ctx context.Context, tenant, connectorID string) (cidrs, fqdns []string, found bool)) {
	mux.HandleFunc("GET /admin/connectors/{connector_id}/routes", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		cid := r.PathValue("connector_id")
		declared, declaredFQDNs, found := connectorDeclaredRoutes(r.Context(), tenant, cid)
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is absent", cid))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"connector_id": cid, "routes": connectorRouteGov.Routes(tenant, cid, declared, declaredFQDNs)})
	}))
	mux.HandleFunc("POST /admin/connectors/{connector_id}/routes", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "connector routes") {
			return
		}
		tenant := adminTenantIDFromRequest(r)
		cid := r.PathValue("connector_id")
		var req struct {
			Action      string `json:"action"` // hold | unhold | approve | unapprove | add | remove
			CIDR        string `json:"cidr"`
			FQDN        string `json:"fqdn"`
			NetworkID   string `json:"network_id"`
			Description string `json:"description,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector route request: %w", err))
			return
		}
		req.CIDR = strings.TrimSpace(req.CIDR)
		req.FQDN = strings.TrimSpace(req.FQDN)
		req.NetworkID = strings.TrimSpace(req.NetworkID)
		action := strings.ToLower(strings.TrimSpace(req.Action))
		isFQDN := req.FQDN != ""
		isNetwork := req.NetworkID != ""
		// Subnets are defined ONCE as a Named Network (vlan-objects) and REFERENCED by network_id. Two things are
		// deliberately NOT accepted (owner decision 2026-07-18):
		//   1. A connector's self-declared routes — the connector is not an authority on what it may reach.
		//      hold/approve existed to ADOPT such a declaration; adoption is now refused.
		//   2. A raw CIDR typed directly into a binding — a subnet must be a Named Network, so it is defined in
		//      one place and every reference stays in sync. `add` therefore takes fqdn | network_id, never cidr.
		// `remove` still accepts a raw cidr so a legacy raw binding can be cleaned up.
		switch action {
		case "hold", "unhold", "approve", "unapprove":
			writeError(w, http.StatusBadRequest, fmt.Errorf("connector-declared routes are not accepted: adopt/hold of a self-reported CIDR is disabled — define the subnet as a Named Network (Networks page) and bind it by network_id"))
			return
		case "add", "remove":
			// ADD accepts a Named-Network reference or an FQDN — never a raw CIDR. A subnet is defined once as a
			// Named Network and referenced, so it stays in sync everywhere. REMOVE still accepts a raw cidr so a
			// pre-existing raw binding can be cleaned up.
			if action == "add" && req.CIDR != "" {
				writeError(w, http.StatusBadRequest, fmt.Errorf("raw CIDR bindings are not accepted: define %q as a Named Network on the Networks page, then bind it by network_id", req.CIDR))
				return
			}
			set := 0
			for _, present := range []bool{req.CIDR != "", isFQDN, isNetwork} {
				if present {
					set++
				}
			}
			if set != 1 {
				writeError(w, http.StatusBadRequest, fmt.Errorf("provide exactly one of fqdn or network_id (a subnet must be a Named Network referenced by network_id, not a raw cidr)"))
				return
			}
			if req.CIDR != "" {
				if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
					writeError(w, http.StatusBadRequest, fmt.Errorf("cidr %q is not a valid CIDR: %w", req.CIDR, err))
					return
				}
			}
			if isNetwork && action == "add" {
				if o, ok := vlanBoundary.GetObject(req.NetworkID); !namedNetworkVisibleToTenant(o, ok, tenant) {
					writeError(w, http.StatusBadRequest, fmt.Errorf("network_id %q is not a known Named Network", req.NetworkID))
					return
				}
			}
		default:
			writeError(w, http.StatusBadRequest, fmt.Errorf("action must be hold | unhold | approve | unapprove | add | remove"))
			return
		}
		var bindingErr error
		switch action {
		case "hold":
			connectorRouteGov.SetHeld(tenant, cid, req.CIDR, true)
		case "unhold":
			connectorRouteGov.SetHeld(tenant, cid, req.CIDR, false)
		case "approve":
			connectorRouteGov.SetApproved(tenant, cid, req.CIDR, true)
		case "unapprove":
			connectorRouteGov.SetApproved(tenant, cid, req.CIDR, false)
		case "add":
			bindingErr = connectorRouteGov.AddAuthored(tenant, cid, authoredRoute{CIDR: req.CIDR, FQDN: req.FQDN, NetworkID: req.NetworkID, Description: strings.TrimSpace(req.Description)})
		case "remove":
			switch {
			case isNetwork:
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, cid, "net:"+req.NetworkID)
			case isFQDN:
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, cid, "fqdn:"+strings.ToLower(req.FQDN))
			default:
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, cid, req.CIDR)
			}
		}
		if action == "add" || action == "remove" {
			now := time.Now().UTC()
			result := "success"
			if bindingErr != nil {
				result = "error"
			}
			audit := adminSiteAuditLog("admin_route_binding_changed", adminSiteModel{SiteID: cid, TenantID: tenant}, r, evaluator, now)
			audit.ActorUserID = auditActorPrincipal(r)
			kind := "route_binding"
			audit.TargetType, audit.Action, audit.Result = &kind, &action, &result
			audit.Metadata = map[string]any{"network_id": req.NetworkID, "fqdn": req.FQDN, "cidr": req.CIDR, "operation": action}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, now)
			if bindingErr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("Could not save network binding."))
				return
			}
		}
		declared, declaredFQDNs, _ := connectorDeclaredRoutes(r.Context(), tenant, cid)
		writeJSON(w, http.StatusOK, map[string]any{"connector_id": cid, "routes": connectorRouteGov.Routes(tenant, cid, declared, declaredFQDNs)})
	}))
	mux.HandleFunc("GET /admin/connectors", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AN OPERATOR ASKING ABOUT THE DEPLOYMENT WAS ANSWERED ABOUT ITSELF (2026-09-01). Four -verify
		// checks reported "no connector has been added to this deployment yet, so there is nothing here to be
		// inconsistent about" while two connectors were carrying a customer's private access — because the
		// installer asks with the deployment administrator's token and connectors belong to CUSTOMER
		// organizations. The checks were true about the operator's organization and silent about the
		// deployment, and they turned that silence into a pass.
		//
		// The rule is the one the envelope already uses everywhere else: an operator may NAME an organization,
		// a customer naming another is refused rather than redirected.
		tenant, tenantErr := adminTenantForWrite(r, r.URL.Query().Get("tenant_id"))
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		result, err := adminConnectorList(r.Context(), registry, tenant, connectorTunnelStatus)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/connectors/{connector_id}", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		connector, found, err := adminConnectorGet(r.Context(), registry, adminTenantIDFromRequest(r), r.PathValue("connector_id"), connectorTunnelStatus)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is absent", r.PathValue("connector_id")))
			return
		}
		writeJSON(w, http.StatusOK, connector)
	}))
	mux.HandleFunc("POST /admin/connectors/{connector_id}/runtime-secret/rotate", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		var request connectorRuntimeSecretRotateRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &request, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector runtime secret rotation: %w", err))
				return
			}
		}
		now := time.Now()
		result, found, err := adminConnectorRotateRuntimeSecret(r.Context(), registry, adminTenantIDFromRequest(r), r.PathValue("connector_id"), request, now, connectorTunnelStatus)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is absent", r.PathValue("connector_id")))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminConnectorManagementAuditLog("admin_connector_runtime_secret_rotated", result.Connector, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, result)
	}))
	// Operator display name for a connector (rename). Stored as server-managed metadata (survives re-registration
	// + heartbeats). Empty name clears the override (falls back to the connector's own name).
	mux.HandleFunc("POST /admin/connectors/{connector_id}/name", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "connector name") {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode connector name: %w", err))
			return
		}
		reg, ok := registry.(connectorRegistryRenamer)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("connector rename is not supported on this registry backend"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		cid := r.PathValue("connector_id")
		conn, found, err := reg.SetDisplayNameForTenant(tenant, cid, req.Name)
		if err != nil {
			if errors.Is(err, connector.ErrRegistryPersistence) {
				writeError(w, http.StatusServiceUnavailable, errors.New("Connector change could not be confirmed in storage. Reload before retrying."))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is absent", cid))
			return
		}
		now := time.Now()
		dto := adminConnectorFromModel(conn)
		applyConnectorTunnelStatus(&dto, connectorTunnelStatus)
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminConnectorManagementAuditLog("admin_connector_renamed", dto, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, dto)
	}))
	// Decommission a connector: remove it from the registry (Console "Remove"). A live connector that keeps
	// heartbeating would re-register, so this is for connectors that are offline / being retired.
	mux.HandleFunc("DELETE /admin/connectors/{connector_id}", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "connector removal") {
			return
		}
		reg, ok := registry.(connectorRegistryRemover)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("connector removal is not supported on this registry backend"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		cid := r.PathValue("connector_id")
		removed, err := reg.RemoveForTenant(tenant, cid)
		if err != nil {
			if errors.Is(err, connector.ErrRegistryPersistence) {
				writeError(w, http.StatusServiceUnavailable, errors.New("Connector change could not be confirmed in storage. Reload before retrying."))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, fmt.Errorf("connector %s is absent", cid))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminConnectorManagementAuditLog("admin_connector_removed", adminConnector{ID: cid, TenantID: tenant}, r, evaluator, time.Now()), time.Now())
		writeJSON(w, http.StatusOK, map[string]any{"connector_id": cid, "removed": true})
	}))
	// Connector UX Slice 1 (/) + Slice 1b: a Site /
	// Connector Group view that MERGES the persistent Site metadata with the read-only connector projection.
	// Connectors are aggregated by connector_group_id; a persistent Site contributes name/region/expected count/
	// namespace and (via expected count) HA-aware health. Reuses admin.connectors.read + the secret-safe DTO; the
	// bootstrap-secret hash is never returned. With an empty Site store this is byte-for-byte the Slice 1 output.
	mux.HandleFunc("GET /admin/sites", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		result, err := adminSiteListMerged(r.Context(), registry, siteStore, adminTenantIDFromRequest(r), connectorTunnelStatus, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/sites/{site_id}", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		site, found, err := adminSiteGetMerged(r.Context(), registry, siteStore, tenantID, r.PathValue("site_id"), connectorTunnelStatus, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("site %s is absent", r.PathValue("site_id")))
			return
		}
		// Slice 6: layer the additive HA failover-readiness + multi-region blocks onto the detail. Tolerant of nil
		// dependencies (lab default) and tenant-scoped; never mutates the underlying projection.
		site = adminSiteEnrichDetail(r.Context(), site, tenantID, applicationCatalogStore, tenantModelStore, regionMap.Catalog(), evaluator.EdgeRegionID)
		writeJSON(w, http.StatusOK, site)
	}))
	// Slice 1b Site CRUD . Create/upsert and delete a persistent Site;
	// admin.connectors.write gated, tenant-scoped, audited. The bootstrap-secret material is server-managed: a
	// client-supplied hash/rotated-at is ignored (the enrollment-command endpoint is the only issuer).
	mux.HandleFunc("POST /admin/sites", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF THE SITE CATALOGUE (2026-08-23, measured).
		// Sites travel in the config bundle now, so a write accepted here diverges from the fleet — and it does
		// NOT self-correct: a CA written directly to an Edge was still there three minutes later and only
		// vanished when an unrelated change moved the bundle's generation. Same store, same shape.
		//
		// The enrolment command is included because it MUTATES the Site: it mints a bootstrap secret and stores
		// its hash, rotating whatever was there. Issuing one on an Edge would replace the secret the control
		// plane believes it handed out, and the connector holding the older command would be refused.
		if configWriteRejectedWhenSourced(w, configSourceURL, "site catalogue") {
			return
		}

		if siteStore == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("persistent site store is not configured"))
			return
		}
		var site adminSiteModel
		if err := decodeLimitedJSONBody(w, r, &site, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode site: %w", err))
			return
		}
		// ★★★ AN OPERATOR CREATING A CUSTOMER'S SITE FILED IT UNDER ITSELF (2026-09-02, measured while walking
		// the connector lane on a fresh deployment). This took the organization from the SESSION and ignored the
		// one the body named, so a Site created for a customer was written under the operator — and because the
		// site_id is the customer's, the fleet's bundle then carried TWO Sites with the same id, one of them
		// belonging to nobody who would ever use it. The connector presenting the customer's bootstrap secret
		// was refused, and the reason it was given named the secret rather than the ownership.
		//
		// One rule, the one the envelope uses everywhere else: an operator may name an organization, a customer
		// naming another is refused rather than quietly redirected into its own.
		tenantID, tenantErr := adminTenantForWrite(r, site.TenantID)
		if tenantErr != nil {
			writeError(w, http.StatusForbidden, tenantErr)
			return
		}
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant_id is required"))
			return
		}
		// Bind the resolved tenant and strip server-managed secret material from client input.
		site.TenantID = tenantID
		site.BootstrapSecretHash = ""
		site.BootstrapSecretRotatedAt = nil
		now := time.Now()
		saved, err := siteStore.Upsert(r.Context(), site, now)
		if err != nil {
			writeAdminSiteStoreError(w, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminSiteAuditLog("admin_site_upserted", saved, r, evaluator, now), now)
		detail, _, derr := adminSiteGetMerged(r.Context(), registry, siteStore, tenantID, saved.SiteID, connectorTunnelStatus, now)
		if derr != nil {
			writeError(w, http.StatusBadRequest, derr)
			return
		}
		detail = adminSiteEnrichDetail(r.Context(), detail, tenantID, applicationCatalogStore, tenantModelStore, regionMap.Catalog(), evaluator.EdgeRegionID)
		writeJSON(w, http.StatusOK, detail)
	}))
	mux.HandleFunc("DELETE /admin/sites/{site_id}", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF THE SITE CATALOGUE (2026-08-23, measured).
		// Sites travel in the config bundle now, so a write accepted here diverges from the fleet — and it does
		// NOT self-correct: a CA written directly to an Edge was still there three minutes later and only
		// vanished when an unrelated change moved the bundle's generation. Same store, same shape.
		//
		// The enrolment command is included because it MUTATES the Site: it mints a bootstrap secret and stores
		// its hash, rotating whatever was there. Issuing one on an Edge would replace the secret the control
		// plane believes it handed out, and the connector holding the older command would be refused.
		if configWriteRejectedWhenSourced(w, configSourceURL, "site catalogue") {
			return
		}

		if siteStore == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("persistent site store is not configured"))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant_id is required"))
			return
		}
		siteID := strings.TrimSpace(r.PathValue("site_id"))
		if siteID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("site_id is required"))
			return
		}
		now := time.Now()
		if err := siteStore.Delete(r.Context(), tenantID, siteID); err != nil {
			writeAdminSiteStoreError(w, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminSiteAuditLog("admin_site_deleted", adminSiteModel{SiteID: siteID, TenantID: tenantID}, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, map[string]any{"site_id": siteID, "deleted": true})
	}))
	// Site Networks (docs/site_private_access_design.md): the networks a SITE serves, bound ONCE to the site and
	// served by ALL its connectors (active + standby are interchangeable). GET lists them; POST binds/unbinds a
	// CIDR, a hostname (FQDN), or a Named-Network reference. Keyed by the site (connector group), never per-connector.
	mux.HandleFunc("GET /admin/sites/{site_id}/networks", adminEndpoint("admin.connectors.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		siteID := strings.TrimSpace(r.PathValue("site_id"))
		if siteID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("site_id is required"))
			return
		}
		rows := []governedRoute{}
		if connectorRouteGov != nil {
			rows = connectorRouteGov.Routes(tenant, siteID, nil, nil)
		}
		writeJSON(w, http.StatusOK, map[string]any{"site_id": siteID, "networks": rows})
	}))
	mux.HandleFunc("POST /admin/sites/{site_id}/networks", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "site networks") {
			return
		}
		if connectorRouteGov == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("route governance is not configured"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		siteID := strings.TrimSpace(r.PathValue("site_id"))
		if siteID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("site_id is required"))
			return
		}
		var req struct {
			Action      string `json:"action"` // add | remove
			CIDR        string `json:"cidr"`
			FQDN        string `json:"fqdn"`
			NetworkID   string `json:"network_id"`
			Description string `json:"description,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode site network request: %w", err))
			return
		}
		req.CIDR, req.FQDN, req.NetworkID = strings.TrimSpace(req.CIDR), strings.TrimSpace(req.FQDN), strings.TrimSpace(req.NetworkID)
		action := strings.ToLower(strings.TrimSpace(req.Action))
		// Same rule as the connector binding: a subnet is a Named Network referenced by network_id, never a raw
		// CIDR typed here. ADD refuses a raw cidr; REMOVE still accepts one to clean up a legacy binding.
		if action == "add" && req.CIDR != "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("raw CIDR bindings are not accepted: define %q as a Named Network on the Networks page, then bind it by network_id", req.CIDR))
			return
		}
		set := 0
		for _, present := range []bool{req.CIDR != "", req.FQDN != "", req.NetworkID != ""} {
			if present {
				set++
			}
		}
		if set != 1 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("provide exactly one of fqdn or network_id (a subnet must be a Named Network referenced by network_id, not a raw cidr)"))
			return
		}
		if req.CIDR != "" {
			if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("cidr %q is not a valid CIDR: %w", req.CIDR, err))
				return
			}
		}
		if req.NetworkID != "" && action == "add" {
			if o, ok := vlanBoundary.GetObject(req.NetworkID); !namedNetworkVisibleToTenant(o, ok, tenant) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("network_id %q is not a known Network", req.NetworkID))
				return
			}
		}
		var bindingErr error
		switch action {
		case "add":
			bindingErr = connectorRouteGov.AddAuthored(tenant, siteID, authoredRoute{CIDR: req.CIDR, FQDN: req.FQDN, NetworkID: req.NetworkID, Description: strings.TrimSpace(req.Description)})
		case "remove":
			switch {
			case req.NetworkID != "":
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, siteID, "net:"+req.NetworkID)
			case req.FQDN != "":
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, siteID, "fqdn:"+strings.ToLower(req.FQDN))
			default:
				bindingErr = connectorRouteGov.RemoveAuthored(tenant, siteID, req.CIDR)
			}
		default:
			writeError(w, http.StatusBadRequest, fmt.Errorf("action must be add | remove"))
			return
		}
		now := time.Now().UTC()
		result := "success"
		if bindingErr != nil {
			result = "error"
		}
		audit := adminSiteAuditLog("admin_route_binding_changed", adminSiteModel{SiteID: siteID, TenantID: tenant}, r, evaluator, now)
		audit.ActorUserID = auditActorPrincipal(r)
		kind := "route_binding"
		audit.TargetType, audit.Action, audit.Result = &kind, &action, &result
		audit.Metadata = map[string]any{"network_id": req.NetworkID, "fqdn": req.FQDN, "cidr": req.CIDR, "operation": action}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, now)
		if bindingErr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("Could not save network binding."))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"site_id": siteID, "networks": connectorRouteGov.Routes(tenant, siteID, nil, nil)})
	}))
	// Slice 1b enrollment command : mint a fresh bootstrap secret for a Site,
	// persist ONLY its hash, and return the plaintext + rendered dsse-connector command EXACTLY ONCE. An optional
	// edge_url in the body fills the --edge-url; absent, a placeholder is rendered for the operator to complete.
	mux.HandleFunc("POST /admin/sites/{site_id}/enrollment-command", adminEndpoint("admin.connectors.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF THE SITE CATALOGUE (2026-08-23, measured).
		// Sites travel in the config bundle now, so a write accepted here diverges from the fleet — and it does
		// NOT self-correct: a CA written directly to an Edge was still there three minutes later and only
		// vanished when an unrelated change moved the bundle's generation. Same store, same shape.
		//
		// The enrolment command is included because it MUTATES the Site: it mints a bootstrap secret and stores
		// its hash, rotating whatever was there. Issuing one on an Edge would replace the secret the control
		// plane believes it handed out, and the connector holding the older command would be refused.
		if configWriteRejectedWhenSourced(w, configSourceURL, "site catalogue") {
			return
		}

		if siteStore == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("persistent site store is not configured"))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant_id is required"))
			return
		}
		var request struct {
			EdgeURL string `json:"edge_url"`
		}
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &request, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode enrollment command request: %w", err))
				return
			}
		}
		now := time.Now()
		enrollEdgeURL := strings.TrimSpace(config.ConnectorEnrollmentEdgeURL)
		if strings.TrimSpace(request.EdgeURL) != "" {
			enrollEdgeURL = strings.TrimSpace(request.EdgeURL)
		}
		// ★★★ A COMMAND WITH AN EMPTY FLAG IN IT IS NOT A COMMAND (2026-08-23, measured). Issued from the
		// reference deployment's CONTROL PLANE — which is where an operator naturally is, because it holds the
		// authority — this returned 200 and a command whose token carried edge_url:"" and no pinned CA. Run as
		// printed, the connector rejected it before its first connection:
		//
		//	connector enrollment: token is missing edge_url or site
		//
		// The node had neither -connector-enrollment-edge-url nor -connector-enrollment-edge-ca set (the Edge
		// has both), and nothing said so: the screen minted a credential, wrote an audit record, rotated the
		// Site's bootstrap secret — invalidating any command issued before it — and handed back something that
		// could never work. Refusing is the whole fix; the operator is told which flag to set, and the previous
		// command they were holding still works because nothing was rotated.
		//
		// The CA is required for the same reason and not merely nice to have: a connector's first act is to
		// hand a CSR to something claiming to be its Edge, so an unpinned first connection is the one that
		// matters most.
		if enrollEdgeURL == "" {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"this node cannot issue an enrollment command because it does not know the Edge address a "+
					"connector should dial: set -connector-enrollment-edge-url on it (the Edge's connector-facing "+
					"URL), or pass edge_url in the request. Nothing was issued, so any command already in use is "+
					"unaffected"))
			return
		}
		if strings.TrimSpace(config.ConnectorEnrollmentEdgeCAPEM) == "" {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"this node cannot issue an enrollment command because it holds no Edge transport CA to pin: set "+
					"-connector-enrollment-edge-ca on it. Without it the connector's first connection — the one "+
					"that carries its CSR — would trust anything. Nothing was issued"))
			return
		}
		// ★★★ AND THE ORGANIZATION'S OWN DOOR, ON THE LINE UNDER THE ONE THAT ALREADY READ IT (2026-09-07).
		// EdgeEndpoints has been per-organization since 2026-08-29; EdgeCAPEM beside it is a node-wide flag
		// holding the deployment anchor, so a connector was handed this organization's REGIONS and the
		// deployment's NAME and ROOT. Measured on twenty organizations, each of which had a door of its own
		// answering in all three regions: twenty connectors, twenty deployment-root pins.
		//
		// The guard is the agent profile's, because the failure it prevents is the agent profile's: a name
		// nothing serves turns every dial into a verification failure. Both halves or neither.
		params := enrollmentTokenParams{
			EdgeURL:       enrollEdgeURL,
			EdgeEndpoints: connectorEnrollmentEndpointList(tenantID),
			StateDir:      strings.TrimSpace(config.ConnectorEnrollmentStateDir),
			EdgeCAPEM:     config.ConnectorEnrollmentEdgeCAPEM,
		}
		if config.TenantTransportAuthority != nil {
			if serverName, inForceSince, _, _, known := config.TenantTransportAuthority.StateFor(tenantID); known &&
				strings.TrimSpace(serverName) != "" && strings.TrimSpace(inForceSince) != "" {
				// AnchorsFor returns the SET, because a rotation overlays rather than swaps and a connector
				// must trust the outgoing anchor until every Edge has moved. Joined into one PEM, which is
				// what the connector's pin file already is.
				if anchors := strings.TrimSpace(strings.Join(config.TenantTransportAuthority.AnchorsFor(tenantID), "\n")); anchors != "" {
					params.OrganizationServerName = strings.TrimSpace(serverName)
					params.OrganizationEnrolmentServerName = organizationEnrolmentName(params.OrganizationServerName)
					params.OrganizationAnchorsPEM = anchors + "\n"
				}
			}
		}
		result, found, err := adminSiteEnrollmentCommandIssue(r.Context(), siteStore, tenantID, r.PathValue("site_id"), params, now)
		if err != nil {
			writeAdminSiteStoreError(w, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("site %s is absent", r.PathValue("site_id")))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminSiteAuditLog("admin_site_enrollment_command_issued", adminSiteModel{SiteID: result.SiteID, TenantID: tenantID, BootstrapSecretHash: connectorRuntimeSecretHash(result.BootstrapSecret)}, r, evaluator, now), now)
		writeJSON(w, http.StatusOK, result)
	}))
}

// Keep storage paths and internal error details out of the administrative response.
func writeAdminSiteStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, errAdminSitePersistence) {
		log.Printf("site storage error: %v", err)
		writeError(w, http.StatusInternalServerError, errAdminSitePersistence)
		return
	}
	writeError(w, http.StatusBadRequest, err)
}

// namedNetworkVisibleToTenant answers whether this caller may REFERENCE that Named Network.
//
// ★★ THE EXISTENCE CHECK WAS DEPLOYMENT-WIDE WHILE THE RESOLVER WAS NOT (2026-08-17, found by reading the
// by-id write routes one at a time after the "what can a customer write" sweep). Both binding routes accepted
// any network_id on the NODE — vlanBoundary.GetObject(id), no tenant — while the resolver that later expands
// the reference to CIDRs refuses a foreign one. The two halves disagreed, and the disagreement was silent in
// both directions:
//
//   - an EXISTENCE ORACLE: 200 for a network id that exists in ANOTHER organization, 400 for one that exists
//     nowhere. A customer could confirm another organization's network names one guess at a time.
//   - a BINDING THAT CAN NEVER WORK: the reference is accepted and stored, and resolves to nothing forever.
//     The site shows a route that does not route, and nothing says why.
//
// The CIDRs were never disclosed — the resolver's tenant check held — so what leaked is the reference, not
// the contents, and what broke is a write the product accepted knowing it would never honour it.
//
// Same rule as the resolver, in the same words: an object carrying no tenant is the deployment's and stays
// visible, which is what deviceGroupVisibleToTenant settled for every other object.
func namedNetworkVisibleToTenant(o model.VLANObject, ok bool, tenant string) bool {
	if !ok {
		return false
	}
	owner := strings.TrimSpace(o.TenantID)
	return owner == "" || strings.TrimSpace(tenant) == "" || strings.EqualFold(owner, strings.TrimSpace(tenant))
}
