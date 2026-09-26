package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"net/url"
	"strings"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/edgeplane"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/revocation"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	sessionstore "github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// connectorApplicationDeps carries the private-app (connector application) data-plane
// dependencies. One value is built in newServerWithConfig and shared by every route
// that dispatches here. Every field is set once during construction and read-only
// afterwards — the handler must not treat this as a mutable service locator.
type connectorApplicationDeps struct {
	evaluator                 decision.Evaluator
	policyStore               policy.RuntimeStore
	writer                    *logs.Writer
	registry                  connectorRegistryStore
	tunnelManager             *tunnel.Manager
	sessionStore              *sessionstore.Store
	deviceStore               deviceRuntimeStore
	proxyClient               *http.Client
	routeProfiles             map[string]edgeplane.ApplicationRouteProfile
	applicationCatalogStore   appcatalog.RuntimeStore
	humanApprovals            *humanapproval.Store
	delegatedGrants           *delegatedgrant.Store
	nonHumanIdentities        nhi.RuntimeStore
	decisionStore             *accessdecision.Store
	domainEventOutbox         domainEventOutboxWriter
	usageMeters               usagemeter.UsageMeterRuntimeStore
	eastWestAuthChallenges    *eastwest.AuthChallengeStore
	workloadAttestationSecret string
	devMode                   bool
	workloadAttestations      runtimeWorkloadAttestationNonceStore
	highRisk                  *revocation.HighRiskOverlay
	enrolledLedger            *enrolledinventory.Ledger
}

func handleConnectorApplication(w http.ResponseWriter, r *http.Request, deps connectorApplicationDeps) {
	policyStore := deps.policyStore
	writer := deps.writer
	registry := deps.registry
	tunnelManager := deps.tunnelManager
	sessionStore := deps.sessionStore
	deviceStore := deps.deviceStore
	proxyClient := deps.proxyClient
	routeProfiles := deps.routeProfiles
	applicationCatalogStore := deps.applicationCatalogStore
	humanApprovals := deps.humanApprovals
	delegatedGrants := deps.delegatedGrants
	nonHumanIdentities := deps.nonHumanIdentities
	decisionStore := deps.decisionStore
	domainEventOutbox := deps.domainEventOutbox
	usageMeters := deps.usageMeters
	eastWestAuthChallenges := deps.eastWestAuthChallenges
	workloadAttestationSecret := deps.workloadAttestationSecret
	devMode := deps.devMode
	workloadAttestations := deps.workloadAttestations
	highRisk := deps.highRisk
	enrolledLedger := deps.enrolledLedger
	evaluator := runtimeEvaluatorForPolicyStore(deps.evaluator, policyStore)
	applicationID := r.PathValue("application_id")
	if applicationID == "" {
		// ★ NO APPLICATION MEANS NO ANSWER, NOT A SAMPLE ONE (2026-09-04). This used to fall back to
		// "app_dummy_https", so a request that named no application was served as if it had named the lab's
		// sample one — and on a deployment where nothing is called that, the caller got "connector for
		// application app_dummy_https is not registered": an error naming an application they never asked for.
		writeError(w, http.StatusBadRequest, fmt.Errorf("no application named in the request path"))
		return
	}
	conn, ok, err := connectorForApplication(r.Context(), r, registry, applicationCatalogStore, evaluator.PolicyBundle.TenantID, applicationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("connector for application %s is not registered", applicationID))
		return
	}

	// Slice 2: overlay PUBLISHED catalog routes onto the startup file routes for the connector's tenant. The
	// file route map stays the fallback for un-published apps (lab invariant).
	routeProfiles = edgeplane.RouteProfilesWithPublishedCatalog(routeProfiles, applicationCatalogStore, conn.TenantID)

	baseReq := decisionRequestForApplicationRoute(r, conn, applicationID, routeProfiles)
	if r.Method == http.MethodConnect {
		baseReq = decisionRequestForApplicationConnect(r, conn, applicationID, routeProfiles)
	}
	req := enrichDecisionRequestWithSession(baseReq, sessionStore)
	req = enrichDecisionRequestWithRisk(req, deviceStore, highRisk, enrolledLedger)
	req = deriveDecisionRequestActor(req, delegatedGrants)
	var attestation runtimeWorkloadAttestationEvidence
	req, attestation, err = enrichDecisionRequestWithRuntimeAttestation(r, req, workloadAttestationSecret, devMode, workloadAttestations, time.Now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	dec := evaluateWithRuntimeEvidence(r.Context(), evaluator, req, humanApprovals, delegatedGrants, nonHumanIdentities, time.Now())
	eastwest.TouchGrantIfSatisfied(policyStore, req, dec, time.Now())
	annotateRuntimeWorkloadAttestationMetadata(&dec, attestation)
	recordNonHumanIdentityRuntimeUse(r.Context(), nonHumanIdentities, &dec, time.Now())
	decisionStore.Upsert(dec)
	recordDecisionMetric(dec.Decision)
	if err := appendAccessDecisionLogs(r.Context(), writer, domainEventOutbox, dec, time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	usagemeter.RecordUsageMeterDecision(usageMeters, dec, time.Now())

	details := map[string]any{
		"access_decision_id": dec.ID,
		"application_id":     applicationID,
		"decision":           dec.Decision,
		"destination_port":   req.DestinationPort,
		"reason_codes":       dec.ReasonCodes,
		"service_family":     req.ServiceFamily,
		"tunnel_id":          nil,
	}
	tunnelSession, tunnelAvailable := tunnelManager.Get(conn.ID)
	if tunnelAvailable {
		details["tunnel_id"] = tunnelSession.TunnelID
	}
	if eastwest.RequiresAuthentication(dec.Decision) {
		// East-west authenticate mode (E2): HOLD the flow at the Edge -- the upstream destination is NOT
		// dialed -- and record a pending challenge bound to (identity x device x destination x protocol).
		// The OOB browser ceremony (E4) + ephemeral grant (E3) release it. Authoritative hold is here
		// because the endpoint is untrusted and the Edge is the only bypass-resistant chokepoint.
		challenge := eastWestAuthChallenges.Create(eastwest.BuildAuthChallenge(req), time.Now())
		details["challenge_id"] = challenge.ID
		details["east_west_hold"] = true
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_route_held_pending_authentication", conn, details), time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Boundary checkpoint (non-secret enum: protocol only; never IP/host/secret).
		logDebugf("east_west_hold_started tenant=%s protocol=%s challenge=%s", challenge.TenantID, challenge.Protocol, challenge.ID)
		writeJSON(w, http.StatusUnauthorized, eastwest.AuthChallengeResponse{
			SchemaVersion:       "east_west_auth_challenge.v1",
			Decision:            dec.Decision,
			ChallengeID:         challenge.ID,
			Destination:         challenge.Destination,
			Protocol:            challenge.Protocol,
			CeremonyURL:         "/auth/oidc/login?challenge_id=" + url.QueryEscape(challenge.ID),
			ExpiresAt:           challenge.ExpiresAt,
			NoSecretAttestation: true,
		})
		return
	}
	if !decisionPermitsConnectorRoute(dec.Decision) {
		if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_route_denied", conn, details), time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if decisionRequiresOIDCRedirect(dec.Decision) && wantsHTMLResponse(r) {
			loginPath := "/auth/oidc/login"
			if returnTo, ok := connectorApplicationReturnTo(r); ok {
				loginPath += "?return_to=" + url.QueryEscape(returnTo)
			}
			http.Redirect(w, r, loginPath, http.StatusFound)
			return
		}
		writeJSON(w, statusForDecision(dec.Decision), dec)
		return
	}

	if err := appendConnectorLog(r.Context(), writer, domainEventOutbox, connectorAudit("connector_route_allowed", conn, details), time.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if r.Method == http.MethodConnect {
		if !tunnelAvailable {
			writeError(w, http.StatusBadGateway, fmt.Errorf("connector tunnel is required for CONNECT application %s", applicationID))
			return
		}
		edgeplane.ProxyConnectViaTunnel(w, r, tunnelSession, conn, dec, req, connectorAuditAppender(writer, domainEventOutbox), applicationID, routeProfiles)
		return
	}
	// Published web private app (publish_protocol=web with a routable destination): proxy the HTTP GET over the
	// connector tunnel's CONNECT (FrameTCPOpen-to-destination) path so it reaches the PUBLISHED destination,
	// instead of the legacy privateBaseURL HTTP frame (which targets the connector's built-in server and ignores
	// the published destination). Requires a live tunnel; otherwise fall through to the legacy path. Authorization
	// already ran above (Published != Allow); the connector authorizes the destination via reachable_routes.
	if tunnelAvailable && publishedWebAppRoute(r.Context(), applicationCatalogStore, conn.TenantID, applicationID) {
		edgeplane.ProxyPublishedWebAppViaTunnel(w, r, tunnelSession, conn, dec, req, connectorAuditAppender(writer, domainEventOutbox), applicationID, routeProfiles)
		return
	}
	if tunnelAvailable {
		proxyViaTunnel(w, r, tunnelSession, applicationID, routeProfiles)
		return
	}
	proxyToConnector(w, r, proxyClient, conn.PrivateBaseURL+edgeplane.ApplicationPrivatePath(applicationID, routeProfiles), applicationID, conn.ID, dec)
}

func decisionRequestForApplicationRoute(r *http.Request, conn model.ConnectorRegistration, applicationID string, routeProfiles map[string]edgeplane.ApplicationRouteProfile) model.DecisionRequest {
	query := r.URL.Query()
	profile := edgeplane.ApplicationRouteProfileFor(applicationID, routeProfiles)
	return model.DecisionRequest{
		TenantID:                  valueOrDefault(query.Get("tenant_id"), conn.TenantID),
		SessionID:                 sessionIDFromRequest(r),
		UserID:                    query.Get("user_id"),
		SubjectUserID:             query.Get("subject_user_id"),
		UserGroups:                splitOptionalCSV(query.Get("user_groups")),
		ActorNHIID:                query.Get("actor_nhi_id"),
		DelegatedAccessGrantID:    query.Get("delegated_access_grant_id"),
		AgentTaskSessionID:        query.Get("agent_task_session_id"),
		ToolID:                    query.Get("tool_id"),
		ToolActionType:            query.Get("tool_action_type"),
		ToolPermissionProfile:     query.Get("tool_permission_profile"),
		ToolVersion:               query.Get("tool_version"),
		ToolSignatureState:        query.Get("tool_signature_state"),
		MCPServerID:               query.Get("mcp_server_id"),
		MCPResourceURI:            query.Get("mcp_resource_uri"),
		MCPAudience:               query.Get("mcp_audience"),
		MCPTokenPassthroughPolicy: query.Get("mcp_token_passthrough_policy"),
		RuntimeEnvironmentID:      query.Get("runtime_environment_id"),
		ContextBoundaryID:         query.Get("context_boundary_id"),
		DataClassification:        query.Get("data_classification"),
		TokenBindingState:         query.Get("token_binding_state"),
		HumanApprovalEventID:      query.Get("human_approval_event_id"),
		DeviceID:                  query.Get("device_id"),
		DeviceTrustLevel:          query.Get("device_trust_level"),
		ApplicationID:             applicationID,
		ApplicationSensitivity:    profile.ApplicationSensitivity,
		ConnectorID:               conn.ID,
		SourceIP:                  sourceIPFromRequest(r),
		Destination:               profile.Destination,
		DestinationPort:           profile.DestinationPort,
		Protocol:                  profile.Protocol,
		FQDN:                      profile.Destination,
		SNI:                       profile.Destination,
		ServiceFamily:             profile.ServiceFamily,
		ConnectionInitiator:       "client",
		SourceRole:                "managed_endpoint",
		DestinationRole:           profile.DestinationRole,
	}
}

func decisionRequestForApplicationConnect(r *http.Request, conn model.ConnectorRegistration, applicationID string, routeProfiles map[string]edgeplane.ApplicationRouteProfile) model.DecisionRequest {
	profile := edgeplane.ApplicationRouteProfileFor(applicationID, routeProfiles)
	return model.DecisionRequest{
		TenantID:               conn.TenantID,
		SessionID:              sessionIDFromRequest(r),
		ApplicationID:          applicationID,
		ApplicationSensitivity: profile.ApplicationSensitivity,
		ConnectorID:            conn.ID,
		SourceIP:               sourceIPFromRequest(r),
		Destination:            profile.Destination,
		DestinationPort:        profile.DestinationPort,
		Protocol:               profile.Protocol,
		FQDN:                   profile.Destination,
		SNI:                    profile.Destination,
		ServiceFamily:          profile.ServiceFamily,
		ConnectionInitiator:    "client",
		SourceRole:             "managed_endpoint",
		DestinationRole:        profile.DestinationRole,
	}
}

// applicationPublishReview builds the review block that makes "Published != Allow" explicit:
//
//	published_route   — the entry is published AND carries a routable destination (reachability exists)
//	policy_assigned   — an active, route-permitting policy explicitly references this application_id
//	users_allowed_now — distinct named principals (user_id + user_groups) authorized by those policies; 0 when
//	                    no policy is assigned, so a freshly published-but-unbound app authorizes nobody.
func applicationPublishReview(entry appcatalog.Entry, evaluator decision.Evaluator, policyStore policy.RuntimeStore) map[string]any {
	evaluator = runtimeEvaluatorForPolicyStore(evaluator, policyStore)
	policyAssigned, usersAllowedNow := applicationPolicyAssignment(entry.ApplicationID, evaluator)
	return map[string]any{
		"published_route":   entry.Published && entry.Status != "disabled" && strings.TrimSpace(entry.Destination) != "",
		"policy_assigned":   policyAssigned,
		"users_allowed_now": usersAllowedNow,
	}
}

// applicationPolicyAssignment reports whether any active, route-permitting policy explicitly references the
// application (via an application_id condition) and how many distinct named principals those policies
// authorize. It deliberately requires an explicit application_id reference (not a broad base-allow) so the
// review reflects an intentional binding and the "no policy -> 0 users" fail-closed message is truthful.
func applicationPolicyAssignment(applicationID string, evaluator decision.Evaluator) (bool, int) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return false, 0
	}
	assigned := false
	principals := map[string]bool{}
	for _, p := range evaluator.Policies {
		if p.Status != "active" {
			continue
		}
		if !decisionPermitsConnectorRoute(p.Action.Decision) {
			continue
		}
		if !policyConditionReferences(p.Conditions, "application_id", applicationID) {
			continue
		}
		assigned = true
		for _, v := range policyConditionStringValues(p.Conditions, "user_id") {
			principals["user:"+v] = true
		}
		for _, v := range policyConditionStringValues(p.Conditions, "user_groups") {
			principals["group:"+v] = true
		}
	}
	return assigned, len(principals)
}
