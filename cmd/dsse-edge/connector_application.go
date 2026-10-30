package main

import (
	"context"
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
	"github.com/lantern-networks/dsse-core/humanidentity"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
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

// Only the /clientless/apps front door may put an already checked IdP session
// here. The relay must not re-read a client-controlled session_id query value.
type verifiedClientlessSessionKey struct{}

func withVerifiedClientlessSession(r *http.Request, session model.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), verifiedClientlessSessionKey{}, session))
}

func verifiedClientlessSessionFromRequest(r *http.Request) (model.Session, bool) {
	session, ok := r.Context().Value(verifiedClientlessSessionKey{}).(model.Session)
	return session, ok && session.ID != "" && session.TenantID != ""
}

// Browsers authenticate the clientless front door with its session cookie.
// Query/header session IDs are not proof for this public browser route.
func clientlessBrowserSession(r *http.Request, store *sessionstore.Store) (model.Session, bool) {
	if store == nil {
		return model.Session{}, false
	}
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		return model.Session{}, false
	}
	return store.GetActiveAt(cookie.Value, time.Now())
}

// Agent application GETs may carry a session in a header or cookie, but the
// query string cannot override the browser cookie or assert another actor.
func applicationSessionID(r *http.Request) string {
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return r.Header.Get("x-session-id")
}

func verifiedManagedApplicationDevice(r *http.Request, tenantID string, deps connectorApplicationDeps) (model.Device, bool, error) {
	deviceID, ok := transportDeviceIdentityFromRequest(r)
	if !ok || deviceID == "" {
		return model.Device{}, false, nil
	}
	if deps.tenantCARegistry != nil {
		certTenant, ok := transportTenantFromRequest(r, deps.tenantCARegistry)
		if !ok || certTenant != tenantID {
			return model.Device{}, false, nil
		}
	}
	// A connector certificate also chains to a tenant CA. Its identity is not
	// an enrolled endpoint, even if the same ID was accidentally registered in
	// both stores.
	if deps.registry != nil {
		_, isConnector, err := connectorRegistrationForTenantWithContext(r.Context(), deps.registry, deviceID, tenantID)
		if err != nil {
			return model.Device{}, false, err
		}
		if isConnector {
			return model.Device{}, false, nil
		}
	}
	if deps.deviceStore == nil {
		return model.Device{}, false, nil
	}
	device, found, err := deviceForTenant(deps.deviceStore, tenantID, deviceID)
	if err != nil {
		return model.Device{}, false, err
	}
	if !found || device.TenantID != tenantID || strings.EqualFold(strings.TrimSpace(device.Status), "revoked") {
		return model.Device{}, false, nil
	}
	return device, true, nil
}

// The device record that proved managed status is also the record used for risk
// evaluation. A second storage read could fail after admission and erase an
// administrator's high-risk signal from the policy decision.
type applicationDeviceSnapshotStore struct {
	deviceRuntimeStore
	device model.Device
}

func (s applicationDeviceSnapshotStore) Get(id string) (model.Device, bool) {
	if id == s.device.ID {
		return s.device, true
	}
	return s.deviceRuntimeStore.Get(id)
}

func (s applicationDeviceSnapshotStore) GetByTenant(tenantID, id string) (model.Device, bool, error) {
	if id == s.device.ID && tenantID == s.device.TenantID {
		return s.device, true, nil
	}
	return model.Device{}, false, nil
}

// connectorApplicationDeps carries the private-app (connector application) data-plane
// dependencies. One value is built in newServerWithConfig and shared by every route
// that dispatches here. Every field is set once during construction and read-only
// afterwards — the handler must not treat this as a mutable service locator.
type connectorApplicationDeps struct {
	evaluator                 decision.Evaluator
	configBundleSource        *configBundleSource
	configSyncStatus          *configBundleSyncStatus
	policyStore               policy.RuntimeStore
	writer                    *logs.Writer
	registry                  connectorRegistryStore
	tunnelManager             *tunnel.Manager
	sessionStore              *sessionstore.Store
	tenantCARegistry          *tenantca.TenantCARegistry
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
	humanIdentities           humanidentity.HumanIdentityDirectoryRuntimeStore
	enrolledLedger            *enrolledinventory.Ledger
}

func handleConnectorApplication(w http.ResponseWriter, r *http.Request, deps connectorApplicationDeps) {
	if !configBundleReadyForTraffic(deps.configBundleSource, deps.configSyncStatus) {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("initial policy configuration is not yet applied"))
		return
	}
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
	// Clientless identity is supplied only by the pre-authorized front door.
	// Direct application sessions additionally require an enrolled mTLS device.
	activeSession, clientlessVerified := verifiedClientlessSessionFromRequest(r)
	hasSession := clientlessVerified
	sessionID := ""
	if clientlessVerified {
		sessionID = activeSession.ID
	} else if r.Method == http.MethodGet || r.Method == http.MethodConnect {
		if r.Method == http.MethodGet {
			sessionID = applicationSessionID(r)
		} else {
			sessionID = sessionIDFromRequest(r)
		}
		if sessionID != "" {
			if sessionStore == nil {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("application session is unavailable"))
				return
			}
			var ok bool
			activeSession, ok = sessionStore.GetActiveAt(sessionID, time.Now())
			if !ok {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("application session is inactive"))
				return
			}
			hasSession = true
		}
	}
	callerTenant := evaluator.PolicyBundle.TenantID
	if hasSession {
		callerTenant = activeSession.TenantID
	}
	certificateTenant, hasCertificateTenant := transportTenantFromRequest(r, deps.tenantCARegistry)
	if hasCertificateTenant {
		if hasSession && activeSession.TenantID != certificateTenant {
			writeError(w, http.StatusForbidden, fmt.Errorf("session and device certificate belong to different tenants"))
			return
		}
		callerTenant = certificateTenant
	}
	managedDeviceRecord, managedDevice, deviceErr := verifiedManagedApplicationDevice(r, callerTenant, deps)
	if deviceErr != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("managed device authority cannot be read"))
		return
	}
	if hasSession && !clientlessVerified && !managedDevice {
		writeError(w, http.StatusForbidden, fmt.Errorf("application session requires a verified managed device"))
		return
	}
	if hasSession && !clientlessVerified && activeSession.DeviceID != nil &&
		strings.TrimSpace(*activeSession.DeviceID) != "" && strings.TrimSpace(*activeSession.DeviceID) != managedDeviceRecord.ID {
		writeError(w, http.StatusForbidden, fmt.Errorf("application session belongs to another device"))
		return
	}
	applicationID := r.PathValue("application_id")
	if applicationID == "" {
		// ★ NO APPLICATION MEANS NO ANSWER, NOT A SAMPLE ONE (2026-09-04). This used to fall back to
		// "app_dummy_https", so a request that named no application was served as if it had named the lab's
		// sample one — and on a deployment where nothing is called that, the caller got "connector for
		// application app_dummy_https is not registered": an error naming an application they never asked for.
		writeError(w, http.StatusBadRequest, fmt.Errorf("no application named in the request path"))
		return
	}
	conn, ok, err := connectorForApplication(r.Context(), r, registry, applicationCatalogStore, callerTenant, applicationID)
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
	routeProfiles, err = edgeplane.RouteProfilesWithPublishedCatalog(r.Context(), routeProfiles, applicationCatalogStore, conn.TenantID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("application catalog cannot be read"))
		return
	}
	publishedWebRoute := false
	if r.Method == http.MethodGet {
		publishedWebRoute, err = publishedWebAppRoute(r.Context(), applicationCatalogStore, conn.TenantID, applicationID)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("application catalog cannot be read"))
			return
		}
	}

	baseReq := decisionRequestForApplicationRoute(r, conn, applicationID, routeProfiles)
	if r.Method == http.MethodConnect {
		baseReq = decisionRequestForApplicationConnect(r, conn, applicationID, routeProfiles)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodConnect {
		baseReq.SessionID = sessionID
	}
	if managedDevice {
		baseReq.DeviceID = managedDeviceRecord.ID
		baseReq.SourceRole = "managed_endpoint"
	} else if strings.EqualFold(baseReq.ApplicationSensitivity, "high") {
		writeError(w, http.StatusForbidden, fmt.Errorf("high-sensitivity application requires a verified managed device"))
		return
	}
	baseReq.ConnectorRouteVerified = true // conn was selected by the server above.
	evaluator = runtimeEvaluatorForTenant(deps.evaluator, policyStore, conn.TenantID)
	req := enrichDecisionRequestWithSession(baseReq, sessionStore)
	if !managedDevice {
		// An IdP session's optional device_id is identity metadata, not a
		// transport certificate proving this browser is a managed endpoint.
		req.DeviceID = ""
		req.SourceRole = ""
	}
	req, riskErr := enrichDecisionRequestWithDirectoryRisk(r.Context(), req, deps.humanIdentities, highRisk)
	if riskErr != nil {
		writeError(w, http.StatusServiceUnavailable, riskErr)
		return
	}
	riskDeviceStore := deviceStore
	if managedDevice {
		riskDeviceStore = applicationDeviceSnapshotStore{deviceRuntimeStore: deviceStore, device: managedDeviceRecord}
	}
	req = enrichDecisionRequestWithRisk(req, riskDeviceStore, highRisk, enrolledLedger)
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
	if tunnelAvailable && publishedWebRoute {
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
	profile := edgeplane.ApplicationRouteProfileFor(applicationID, routeProfiles)
	return model.DecisionRequest{
		TenantID:               conn.TenantID,
		SessionID:              "", // supplied only after trusted route/session selection
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
		DestinationRole:        profile.DestinationRole,
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
		SourceRole:             "", // assigned only after enrolled mTLS device proof
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
