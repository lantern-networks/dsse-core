package main

// Private-app (application) admin routes — list/detail/create, Slice 2 publish/unpublish,
// delete, and Slice 3 reachability diagnostics — moved verbatim out of newServerWithConfig
// (Phase 2 route-registration split). Takes serverConfig whole for the publish path's
// catalog/rule/asset deps.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func registerApplicationAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, policyStore policy.RuntimeStore, applicationCatalogStore appcatalog.RuntimeStore, registry connectorRegistryStore, tunnelManager *tunnel.Manager, routeProfiles map[string]edgeplane.ApplicationRouteProfile, tenantModelStore adminTenantModelRuntimeStore, domainEventOutbox domainEventOutboxWriter, configSourceURL string) {
	// The app row and its rule-destination endpoint are separate saves. Never
	// report complete success when the second save (including its term fence) fails.
	partialAsset := func(w http.ResponseWriter, r *http.Request, a model.AuditLog, now time.Time) {
		result, reason := "partial", "Application change was saved, but its rule-destination update was not confirmed."
		a.Result = &result
		a.Reason = &reason
		if a.Metadata == nil {
			a.Metadata = map[string]any{}
		}
		a.Metadata["failed_stage"] = "asset_endpoint"
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, a), now)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": reason + " Retry the operation to finish the rule-destination update.", "partial": true, "failed_stage": "asset_endpoint", "application_id": stringPtrValue(a.TargetID)})
	}
	mux.HandleFunc("GET /admin/applications", adminEndpoint("admin.applications.read", func(w http.ResponseWriter, r *http.Request) {
		options := appcatalog.ListOptions{
			ApplicationType: strings.TrimSpace(r.URL.Query().Get("application_type")),
			Status:          strings.TrimSpace(r.URL.Query().Get("status")),
			Limit:           boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := applicationCatalogStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /admin/applications/{application_id}", adminEndpoint("admin.applications.read", func(w http.ResponseWriter, r *http.Request) {
		application, found, err := applicationCatalogStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("application_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("application %s is absent", r.PathValue("application_id")))
			return
		}
		writeJSON(w, http.StatusOK, application)
	}))
	mux.HandleFunc("POST /admin/applications", adminEndpoint("admin.applications.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "application catalog") {
			return
		}
		var application appcatalog.Entry
		if err := decodeLimitedJSONBody(w, r, &application, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode application catalog entry: %w", err))
			return
		}
		now := time.Now()
		created, err := applicationCatalogStore.Upsert(r.Context(), application, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationCatalogAuditLog(created, evaluator, now)), now)
		writeJSON(w, http.StatusOK, created)
	}))
	// Connector UX Slice 2: publish a Private App. Publishing sets published=true plus the runtime route
	// (destination/port/publish_protocol/connector_group_id) on the catalog entry, which the edge merges on top
	// of the startup file routes. Publishing creates REACHABILITY only — authorization stays with policy
	// (Published != Allow). The response carries a review block (published_route / policy_assigned /
	// users_allowed_now) so the operator sees that publishing alone authorizes no users (fail-closed).
	mux.HandleFunc("POST /admin/applications/{application_id}/publish", adminEndpoint("admin.applications.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "application catalog") {
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		applicationID := strings.TrimSpace(r.PathValue("application_id"))
		var body struct {
			Name                   string `json:"name"`
			Destination            string `json:"destination"`
			DestinationPort        int    `json:"destination_port"`
			PublishProtocol        string `json:"publish_protocol"`
			ConnectorGroupID       string `json:"connector_group_id"`
			ApplicationSensitivity string `json:"application_sensitivity"`
			// Connector UX Slice 5: routing namespace scopes a network (CIDR) route so overlapping ranges can
			// coexist across sites; override_cidr_collision is the explicit high-risk approval that lets an
			// authorized operator (admin.connectors.write) publish a network route despite a detected CIDR collision.
			RoutingNamespace      string `json:"routing_namespace"`
			OverrideCIDRCollision bool   `json:"override_cidr_collision"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode application publish: %w", err))
			return
		}
		now := time.Now()
		entry, found, err := applicationCatalogStore.Get(r.Context(), tenantID, applicationID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			entry = appcatalog.Entry{ApplicationID: applicationID, TenantID: tenantID, ApplicationType: "private_app"}
		}
		if strings.TrimSpace(entry.ApplicationType) == "" {
			entry.ApplicationType = "private_app"
		}
		if name := strings.TrimSpace(body.Name); name != "" {
			entry.Name = name
		}
		entry.Destination = strings.TrimSpace(body.Destination)
		entry.DestinationPort = body.DestinationPort
		if proto := strings.TrimSpace(body.PublishProtocol); proto != "" {
			entry.PublishProtocol = proto
		}
		if group := strings.TrimSpace(body.ConnectorGroupID); group != "" {
			entry.ConnectorGroupID = group
		}
		if namespace := strings.TrimSpace(body.RoutingNamespace); namespace != "" {
			entry.RoutingNamespace = namespace
		}
		if sensitivity := strings.TrimSpace(body.ApplicationSensitivity); sensitivity != "" {
			entry.ApplicationSensitivity = sensitivity
		}
		entry.Published = true
		if strings.TrimSpace(entry.Status) == "" {
			entry.Status = "active"
		}
		// Connector UX Slice 5: a network (CIDR) route must not silently shadow an existing route in the same
		// scope. Detect collisions against the tenant's other published network routes + connector reachable_routes;
		// block with 409 unless an authorized operator (admin.connectors.write) supplies an explicit high-risk
		// override. namespace OR site (connector group) separation avoids a collision; an overlapping CIDR with no
		// namespace is ambiguous and blocked by default. FQDN/web/tcp host routes are not in scope (detect returns
		// nil). Fail-closed: a read error blocks the publish rather than allowing it.
		if strings.TrimSpace(entry.PublishProtocol) == "network" {
			collisions, err := detectPublishCIDRCollisions(r.Context(), applicationCatalogStore, registry, tenantID, applicationID, entry.Destination, entry.RoutingNamespace, entry.ConnectorGroupID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("evaluate cidr route collisions: %w", err))
				return
			}
			if len(collisions) > 0 {
				identity, _ := adminIdentityFromRequest(r)
				if !cidrCollisionOverrideAuthorized(identity.Roles, body.OverrideCIDRCollision) {
					writeJSON(w, http.StatusConflict, map[string]any{
						"schema_version": "application_publish_collision.v1",
						"error":          "cidr_route_collision",
						"application_id": applicationID,
						"cidr":           entry.Destination,
						"namespace":      entry.RoutingNamespace,
						"site":           entry.ConnectorGroupID,
						"ambiguous":      strings.TrimSpace(entry.RoutingNamespace) == "",
						"collisions":     collisions,
						"choices":        cidrCollisionChoices(),
						"override": map[string]any{
							"flag":                "override_cidr_collision",
							"requires_permission": "admin.connectors.write",
						},
					})
					return
				}
				// Authorized high-risk override: record the approval, then proceed with the publish.
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationCIDRCollisionOverrideAuditLog(entry, collisions, evaluator, now)), now)
			}
		}
		created, err := applicationCatalogStore.Upsert(r.Context(), entry, tenantID, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Surface the published private app as a selectable rule destination: the Connector Access (east-west)
		// and egress rule forms populate their "Destination" picker from the asset endpoint catalog, which
		// otherwise only holds steered devices + built-in SaaS — so a freshly published app had no way to be
		// targeted by name. Idempotent (stable id keyed by the app), refreshed on every re-publish; removed on
		// unpublish/delete below.
		if addr := strings.TrimSpace(created.Destination); addr != "" && config.AssetStore != nil {
			alias := strings.TrimSpace(created.Name)
			if alias == "" {
				alias = created.ApplicationID
			}
			if _, uerr := config.AssetStore.UpsertEndpointContext(r.Context(), assetcatalog.Endpoint{
				ID: "app-" + created.ApplicationID, TenantID: tenantID, Alias: alias,
				Kind: assetcatalog.KindNetwork, Address: addr, Source: assetcatalog.SourceManual,
			}); uerr != nil {
				partialAsset(w, r, adminApplicationPublishAuditLog(created, evaluator, now, true), now)
				return
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationPublishAuditLog(created, evaluator, now, true)), now)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "application_publish.v1",
			"application":    created,
			"review":         applicationPublishReview(created, evaluator, policyStore),
		})
	}))
	mux.HandleFunc("POST /admin/applications/{application_id}/unpublish", adminEndpoint("admin.applications.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "application catalog") {
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		applicationID := strings.TrimSpace(r.PathValue("application_id"))
		now := time.Now()
		entry, found, err := applicationCatalogStore.Get(r.Context(), tenantID, applicationID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("application %s is absent", applicationID))
			return
		}
		entry.Published = false
		created, err := applicationCatalogStore.Upsert(r.Context(), entry, tenantID, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Remove the rule-destination endpoint surfaced at publish (no longer reachable once unpublished).
		if config.AssetStore != nil {
			if _, err := config.AssetStore.DeleteEndpointContext(r.Context(), tenantID, "app-"+applicationID); err != nil {
				partialAsset(w, r, adminApplicationPublishAuditLog(created, evaluator, now, false), now)
				return
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationPublishAuditLog(created, evaluator, now, false)), now)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "application_publish.v1",
			"application":    created,
			"review":         applicationPublishReview(created, evaluator, policyStore),
		})
	}))
	// Delete an operator-authored application. Tenant-scoped (a tenant can only delete its own ids) and
	// fail-closed: deleting an entry removes it from the catalog, which also drops it from
	// edgeplane.RouteProfilesWithPublishedCatalog — so a PUBLISHED app becomes unreachable on delete (no separate unpublish
	// needed). Config-seed entries (route profile / SaaS catalog derived) are NOT deletable (404): they are
	// reconstructed from configuration on every boot, so a delete would only reappear on restart. Any policy that
	// references the deleted application_id is left untouched (it simply matches no application now); the Console
	// confirm dialog reminds the operator to tidy such policies manually.
	mux.HandleFunc("DELETE /admin/applications/{application_id}", adminEndpoint("admin.applications.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "application catalog") {
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant_id is required"))
			return
		}
		applicationID := strings.TrimSpace(r.PathValue("application_id"))
		if applicationID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("application_id is required"))
			return
		}
		now := time.Now()
		err := applicationCatalogStore.Delete(r.Context(), tenantID, applicationID)
		switch {
		case err == nil:
			// proceed
		case errors.Is(err, appcatalog.ErrApplicationNotFound):
			// A previous delete may have removed the application but failed to remove
			// its endpoint. Permit the same tenant to finish that cleanup on retry.
			if !refreshAuthoredStores(w, nil, config.AssetStore) {
				return
			}
			found := false
			if config.AssetStore != nil {
				_, found = config.AssetStore.GetEndpoint(tenantID, "app-"+applicationID)
			}
			if !found {
				writeError(w, http.StatusNotFound, fmt.Errorf("application %s is absent", applicationID))
				return
			}
		case errors.Is(err, appcatalog.ErrApplicationNotDeletable):
			writeError(w, http.StatusNotFound, fmt.Errorf("application %s is config-seeded and cannot be deleted (it is derived from configuration and would be re-created on restart); disable or edit configuration instead", applicationID))
			return
		default:
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Drop the rule-destination endpoint surfaced at publish (the app no longer exists).
		if config.AssetStore != nil {
			if _, err := config.AssetStore.DeleteEndpointContext(r.Context(), tenantID, "app-"+applicationID); err != nil {
				partialAsset(w, r, adminApplicationDeleteAuditLog(tenantID, applicationID, evaluator, now), now)
				return
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationDeleteAuditLog(tenantID, applicationID, evaluator, now)), now)
		writeJSON(w, http.StatusOK, map[string]any{"application_id": applicationID, "deleted": true})
	}))
	// Connector UX Slice 3: reachability diagnostics. Probe the application's destination through the connector
	// that fronts it (DNS/TCP/TLS/HTTP, scoped to reachable_routes on the connector side) and layer a policy
	// dry-run on top. It flows NO real traffic (bounded body-less probe + pure decision evaluate) and is
	// tenant-scoped + secret-safe (the audit records the verdict only). Connector/tunnel absent => fail-closed
	// no_connector / no_tunnel result (lab with 0 connectors returns "no reachable connector").
	mux.HandleFunc("POST /admin/applications/{application_id}/reachability", adminEndpoint("admin.applications.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		applicationID := strings.TrimSpace(r.PathValue("application_id"))
		if applicationID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("application_id is required"))
			return
		}
		runtimeEvaluator := runtimeEvaluatorForPolicyStore(evaluator, policyStore)
		merged := edgeplane.RouteProfilesWithPublishedCatalog(routeProfiles, applicationCatalogStore, tenantID)
		profile := edgeplane.ApplicationRouteProfileFor(applicationID, merged)
		conn, connectorFound, err := connectorForApplication(r.Context(), r, registry, applicationCatalogStore, tenantID, applicationID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		var (
			session         *tunnel.Session
			tunnelConnected bool
			prober          reachabilityProber
		)
		if connectorFound {
			// ★★★ REACH IT THE WAY A FLOW REACHES IT (2026-09-03, measured — see
			// edgeplane/a_diagnostic_must_reach_the_way_a_flow_reaches.go). Asking only this node's tunnel
			// manager reported "tunnel not connected" for a connector on another region's door while a steered
			// device was fetching the app through this very Edge over the peer-Edge relay.
			var probeRegions []string
			if tenantModelStore != nil {
				if tenant, terr := tenantModelStore.Get(r.Context(), tenantID); terr == nil {
					probeRegions = tenant.AllowedRegions
				}
			}
			session, _ = edgeplane.ConnectorProbeSession(conn, profile.Destination, evaluator.EdgeRegionID,
				probeRegions, config.MeshEligible, tunnelManager, config.PeerEdges)
			tunnelConnected = session != nil
			if tunnelConnected && session != nil {
				prober = func(ctx context.Context, frame tunnel.Frame) (tunnel.Frame, error) {
					return session.RoundTrip(ctx, frame)
				}
			}
		}
		result := buildReachabilityResult(r.Context(), runtimeEvaluator, tenantID, applicationID, conn, connectorFound, tunnelConnected, profile, prober)
		// Slice 6: layer a ROUTE-LEVEL residency error (distinct from the policy simulation) when the fronting
		// connector's region is outside the tenant's residency boundary — the same fail-closed decision the live
		// egress dialer enforces. Tenant residency comes from the admin tenant model (nil = unpinned, no restriction).
		if connectorFound {
			var allowedRegions []string
			if tenantModelStore != nil {
				if tenant, terr := tenantModelStore.Get(r.Context(), tenantID); terr == nil {
					allowedRegions = tenant.AllowedRegions
				}
			}
			result.RouteError = evaluateReachabilityResidency(conn.EdgeRegionID, evaluator.EdgeRegionID, allowedRegions, config.MeshEligible, profile.Destination)
		}
		now := time.Now()
		auditConn := conn
		if !connectorFound {
			auditConn = model.ConnectorRegistration{TenantID: tenantID}
		}
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("reachability_test_executed", auditConn, reachabilityAuditDetails(applicationID, result)), now); err != nil {
			log.Printf("write reachability audit log: %v", err)
		}
		writeJSON(w, http.StatusOK, result)
	}))
	// clientless published-app access (agentless): evaluate whether an IdP-authenticated clientless
	// (no-agent, browser front-door) user is authorized to reach a published app — reduced-trust tier, only
	// apps published behind a connector for the tenant, managed-device-only apps excluded. This is the
	// authorization-contract surface; the production OIDC front-door session + reverse proxy is the deferred
	// real-environment piece. Behind admin auth as an operator authorization check (no new public surface).
}
