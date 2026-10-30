package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/authportal"
	"github.com/lantern-networks/dsse-core/authrollout"
	grantstore "github.com/lantern-networks/dsse-core/grantstore"
	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
	oidcbroker "github.com/lantern-networks/dsse-core/oidcbroker"
)

// clientlessBroker is the end-user OIDC relying-party front door (slice 3, clientless-first): it redirects an
// unauthenticated browser to the tenant's required IdP, takes the callback, exchanges the code, validates the
// ID token (oidcbroker), and mints a continuously-revocable grant bound to the verified user. The required
// IdP is the policy's when set, else the tenant default (registry.Resolve); an unregistered IdP fails closed.
// See docs/idp_federated_authentication_design.md.
type clientlessBroker struct {
	rollout              *authRolloutRuntime
	draining             *atomic.Bool
	registry             *idpregistry.Store
	grants               *grantstore.Store
	authority            *grantCPReporter
	authorityRequired    bool
	requireFleetRecovery bool
	checkTenantRegion    sharedFleetResidencyCheck
	// Publish before the completion response: another Edge may receive the
	// user's next request before the periodic reconciliation runs.
	publishGrants     func(context.Context)
	httpClient        *http.Client
	selfBaseURL       string // e.g. https://edge:8443 — used to build the RP redirect_uri
	tenantID          string
	grantTTL          time.Duration
	cookieName        string
	signer            *deviceBindingSigner // verifies the device the gate signed into the start URL (per-device grants)
	recoverySharedKey bool                 // only the configured deployment key may carry a ceremony across Portals

	mu            sync.Mutex
	pending       map[string]pendingAuth
	ceremonies    map[string]*authCeremony
	startRates    map[authRateKey]authRateWindow
	confirmations map[string]authDestinationConfirmation
}

type pendingAuth struct {
	osPrincipal, osSession string
	bindingRevision        string // exact assignment observed at start; unrelated edits do not invalidate this ceremony
	consuming              bool   // reserve callback work until it finishes, including anonymous starts
	providerDigest         [32]byte
	requestID              string
	browserHash            [32]byte
	idpID                  string
	nonce                  string
	codeVerifier           string
	redirectURI            string
	returnTo               string
	requiredACR            string
	requiredAMR            []string
	maxAgeSeconds          *int64
	grantTTLSeconds        *int64
	reauthenticateAfter    time.Time
	boundDevice            string // the verified (T) device the gate signed into the start URL; "" = tenant-wide grant
	tenantID               string // the organization the held flow belonged to, signed into the start URL beside the device
	deadline               time.Time
	createdAt              time.Time
	sourceIP               string // socket peer, never an untrusted forwarding header
	recovered              bool   // decoded from a sealed state after the starting Portal was lost
}

const pendingAuthTTL = 10 * time.Minute

func newClientlessBroker(registry *idpregistry.Store, grants *grantstore.Store, httpClient *http.Client, selfBaseURL, tenantID string, grantTTL time.Duration, signer *deviceBindingSigner) *clientlessBroker {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	// The broker OWNS the outbound-redirect SSRF policy: the OIDC token/JWKS fetches target the registered IdP
	// and should return 200, so never follow 30x — a redirect-driven SSRF from a compromised IdP is closed. Set
	// it whenever the (possibly caller-supplied) client did not, so the production caller's plain
	// &http.Client{Timeout:...} cannot silently follow a malicious redirect.
	if httpClient.CheckRedirect == nil {
		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	if grantTTL <= 0 {
		grantTTL = 8 * time.Hour
	}
	return &clientlessBroker{
		registry: registry, grants: grants, httpClient: httpClient,
		selfBaseURL: strings.TrimRight(selfBaseURL, "/"), tenantID: tenantID, grantTTL: grantTTL,
		cookieName: "dsse_grant", signer: signer, pending: map[string]pendingAuth{}, ceremonies: map[string]*authCeremony{},
	}
}

func (b *clientlessBroker) register(mux *http.ServeMux) {
	registerBrokerHandler(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clientless/auth/start":
			b.handleStart(w, r)
		case "/clientless/auth/callback":
			b.handleCallback(w, r)
		case "/clientless/auth/retry":
			b.handleRetry(w, r)
		case "/clientless/auth/whoami":
			b.handleWhoami(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
}

// handleStart redirects the browser to the required IdP (auth code + PKCE). ?idp= selects a registered IdP
// (else the tenant default); ?return_to= is where to land after success.
func (b *clientlessBroker) handleStart(w http.ResponseWriter, r *http.Request) {
	if b.draining != nil && b.draining.Load() {
		authResponseHeaders(w)
		respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication node is restarting", "Reconnect through another node and request a fresh sign-in link.")
		return
	}
	authResponseHeaders(w)
	if b.requireFleetRecovery && !b.ceremonyRecoveryReady() {
		respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication authority unavailable", "Activate verified fleet ceremony recovery before starting authentication.")
		return
	}
	if _, err := authportal.Origin(b.selfBaseURL); err != nil {
		respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication portal is not configured correctly", "Configure an HTTPS origin without a path for the Portal.")
		return
	}
	if !validAuthQuery(r) {
		respondCeremonyError(w, r, 400, "Sign-in link invalid", "Restart authentication with a fresh link.")
		return
	}
	idp := strings.TrimSpace(r.URL.Query().Get("idp"))
	// ★★★ THE ORGANIZATION IS THE HELD FLOW'S, NOT THIS NODE'S (2026-09-02, measured on the live deployment).
	//
	// This resolved against b.tenantID — the Edge's own policy-bundle organization — so a customer's device
	// was answered "no usable IdP for the tenant" about the OPERATOR's registry, while the customer's own
	// provider sat in this same Edge's registry, applied from the config bundle seconds earlier.
	//
	// It comes from the gate, signed together with the device, because it decides whose identity provider is
	// trusted to mint a grant. An unsigned organization in a client-visible URL would let one customer's
	// device ask to be authenticated by another customer's IdP.
	query := r.URL.Query()
	deviceClaim, tenantClaim, signature := strings.TrimSpace(query.Get("device")), strings.TrimSpace(query.Get("tenant")), strings.TrimSpace(query.Get("device_sig"))
	boundDevice, tenant := b.signer.verifiedBinding(deviceClaim, tenantClaim, signature)
	if query.Has("device") || query.Has("tenant") || query.Has("device_sig") {
		// A broken binding is a refusal, never a broader clientless grant. Also
		// reject duplicate binding parameters rather than choosing one interpretation.
		if b.signer == nil || signature == "" || (deviceClaim == "" && tenantClaim == "") ||
			boundDevice != deviceClaim || tenant != tenantClaim ||
			len(query["device"]) > 1 || len(query["tenant"]) > 1 || len(query["device_sig"]) > 1 {
			respondCeremonyError(w, r, http.StatusUnauthorized, "Sign-in link invalid",
				"Return to your terminal and start the connection again to get a fresh sign-in link.")
			return
		}
	}

	if b.requireFleetRecovery && boundDevice == "" {
		respondCeremonyError(w, r, http.StatusUnauthorized, "Invalid binding", "Start authentication from a verified endpoint request.")
		return
	}

	if b.checkTenantRegion != nil {
		if err := b.checkTenantRegion(r.Context(), tenant); err != nil {
			respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication authority unavailable", "This organization cannot authenticate through this Edge Region.")
			return
		}
	}

	for _, key := range []string{"idp", "acr", "amr", "max_age", "return_to", "requirements_sig", "os_principal", "os_session"} {
		if len(query[key]) > 1 {
			respondCeremonyError(w, r, 401, "Sign-in link invalid", "Restart authentication with a fresh link.")
			return
		}
	}
	if boundDevice != "" || signature != "" {
		origin, err := authportal.Origin(b.selfBaseURL)
		if err != nil || query.Get("portal_origin") != origin {
			respondCeremonyError(w, r, 401, "Wrong authentication portal", "Request a fresh link from your app.")
			return
		}
		want := b.signer.signRequirements(query)
		if want == "" || !hmac.Equal([]byte(query.Get("requirements_sig")), []byte(want)) {
			respondCeremonyError(w, r, 401, "Sign-in link invalid", "Restart authentication with a fresh link.")
			return
		}
	}
	if federatedDestinationScope(query.Get("return_to")) == "" {
		respondCeremonyError(w, r, 400, "Invalid authentication destination", "Start authentication from the application request.")
		return
	}
	if (boundDevice != "" || signature != "") && validateAuthStartLifetime(query, time.Now().UTC()) != nil {
		respondCeremonyError(w, r, 401, "Sign-in link expired", "Return to your app and request a fresh sign-in link.")
		return
	}
	if signature == "" && (query.Has("request_id") || query.Has("issued_at") || query.Has("expires_at")) {
		respondCeremonyError(w, r, 401, "Invalid binding", "Request a fresh sign-in link.")
		return
	}
	var maxAge *int64
	if query.Has("max_age") {
		age, err := strconv.ParseInt(query.Get("max_age"), 10, 64)
		if err != nil || age < 0 || age > 86400 {
			respondCeremonyError(w, r, 400, "Sign-in link invalid", "Invalid authentication age.")
			return
		}
		maxAge = &age
	}
	var grantTTL *int64
	if query.Has("grant_ttl") {
		seconds, err := strconv.ParseInt(query.Get("grant_ttl"), 10, 64)
		if signature == "" || err != nil || !validAuthGrantTTLSeconds(seconds) {
			respondCeremonyError(w, r, 400, "Sign-in link invalid", "Invalid authentication grant lifetime.")
			return
		}
		grantTTL = &seconds
	}
	var methods []string
	if query.Has("amr") {
		for _, method := range strings.Split(query.Get("amr"), ",") {
			if method == "" || strings.ContainsAny(method, " \t\r\n") {
				respondCeremonyError(w, r, 400, "Sign-in link invalid", "Invalid authentication methods.")
				return
			}
			methods = append(methods, method)
		}
	}
	if tenant == "" {
		tenant = b.tenantID
	}
	conn, ok := b.registry.Resolve(tenant, idp)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no usable IdP for organization %q (required %q is not registered)", tenant, idp))
		return
	}
	principal, loginSession := query.Get("os_principal"), query.Get("os_session")
	identityEnabled, identityKnown := b.rollout.deviceUserBindingMode()
	if boundDevice != "" && !identityKnown {
		respondCeremonyError(w, r, 503, "Authentication upgrade state unavailable", "Request a fresh link when authentication services are available.")
		return
	}
	identityRequired := boundDevice != "" && identityEnabled
	bindingRevision := ""
	assignedSubject := ""
	if identityRequired {
		if !validAuthOwner(principal, loginSession) {
			respondCeremonyError(w, r, 403, "Device user is not identified", "Update the agent and start authentication from your own OS session.")
			return
		}
		binding, assigned := conn.AssignedBinding(boundDevice, principal)
		if !assigned {
			respondCeremonyError(w, r, 403, "Device user is not assigned", "Ask your administrator to assign this OS account to your identity provider subject.")
			return
		}
		bindingRevision = binding.Revision
		assignedSubject = binding.Subject
	} else if principal != "" || loginSession != "" {
		respondCeremonyError(w, r, 403, "Device user binding is unavailable", "Request a fresh authentication link after the deployment is ready.")
		return
	}
	if maxAge != nil && *maxAge == 0 && !b.rollout.featureEnabled("single-request-v1") {
		respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication upgrade in progress", "The deployment must confirm all authentication nodes before single-request authentication can be enabled.")
		return
	}
	// Opening a browser is not consent to authorize a new destination. IdP SSO
	// may complete without interaction, so require an explicit same-browser POST
	// before contacting either the authentication authority or the IdP.
	if !b.confirmAuthenticationDestination(w, r, tenant, boundDevice) {
		return
	}
	boundary, boundaryErr := b.reauthenticationBoundary(r.Context(), grantstore.Grant{TenantID: tenant, UserID: assignedSubject, DeviceID: boundDevice, OSPrincipal: principal, IdPID: conn.IdPID, Issuer: conn.Issuer, Scope: federatedDestinationScope(query.Get("return_to"))})
	if boundaryErr != nil {
		respondCeremonyError(w, r, 503, "Authentication authority unavailable", "Try again when authentication services are available.")
		return
	}
	requestMaxAge := authenticationAgeAfterRevocation(maxAge, boundary, time.Now().UTC())
	params := oidcbroker.AuthorizeParams{ACRValues: strings.TrimSpace(query.Get("acr")), MaxAgeSeconds: requestMaxAge, RequiredAMR: methods}
	if err := oidcbroker.ValidateAuthorizeParams(conn, params); err != nil {
		respondCeremonyError(w, r, http.StatusUnprocessableEntity, "Authentication requirements unavailable", err.Error())
		return
	}
	state, err1 := oidcbroker.NewOpaqueToken()
	nonce, err2 := oidcbroker.NewOpaqueToken()
	verifier, err3 := oidcbroker.NewCodeVerifier()
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("generate auth params"))
		return
	}
	redirectURI := b.selfBaseURL + "/clientless/auth/callback"
	// Step-up: the policy's required assurance (carried in the ?acr= query from the gate) is BOTH requested
	// from the IdP (acr_values, so the SAME IdP re-prompts for the stronger factor) AND validated on callback.
	requiredACR := strings.TrimSpace(r.URL.Query().Get("acr"))
	// A supplied device binding was verified above before any pending state was created.
	session, err := ensureBrowserSession(w, r)
	if err != nil {
		writeError(w, 500, fmt.Errorf("generate browser binding"))
		return
	}
	browserHash := sha256.Sum256([]byte(session))
	now := time.Now().UTC()
	requestID := query.Get("request_id")
	csrf, err := oidcbroker.NewOpaqueToken()
	if err != nil {
		writeError(w, 500, fmt.Errorf("generate retry binding"))
		return
	}
	ceremonyDeadline := now.Add(pendingAuthTTL)
	b.mu.Lock()
	b.sweepAuthLocked(now)
	if requestID != "" {
		if existing := b.ceremonies[requestID]; existing != nil {
			if existing.browserHash != browserHash || existing.succeeded {
				b.mu.Unlock()
				respondCeremonyError(w, r, 409, "Sign-in request already used", "Request a fresh link from your app.")
				return
			}
			if !existing.restart {
				existingURL, finished := existing.authorizeURL, existing.finished
				b.mu.Unlock()
				if finished {
					b.ceremonyError(w, r, pendingAuth{requestID: requestID}, 409, "Authentication not completed", "Retry authentication or request a fresh link.")
					return
				}
				navigateToAuthenticationProvider(w, r, existingURL)
				return
			}
			ceremonyDeadline = existing.expires
			csrf = existing.csrf
		}
	}

	if !b.authCapacityForPeerLocked(tenant, boundDevice, authPeerIP(r), requestID) {
		b.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		respondCeremonyError(w, r, 429, "Too many sign-in requests", "Complete or wait for outstanding requests to expire.")
		return
	}
	pa := pendingAuth{
		osPrincipal: principal, osSession: loginSession, bindingRevision: bindingRevision,
		idpID: conn.IdPID, nonce: nonce, codeVerifier: verifier, redirectURI: redirectURI, requiredACR: requiredACR, requiredAMR: methods, maxAgeSeconds: maxAge, grantTTLSeconds: grantTTL, reauthenticateAfter: boundary,
		returnTo: strings.TrimSpace(query.Get("return_to")), boundDevice: boundDevice,
		tenantID: tenant, sourceIP: authPeerIP(r), createdAt: now, deadline: ceremonyDeadline, requestID: requestID, browserHash: browserHash, providerDigest: authProviderDigest(conn),
	}
	if requestID != "" && boundDevice != "" && b.ceremonyRecoveryReady() {
		sealed, sealErr := b.sealAuthState(pa)
		if sealErr != nil {
			b.mu.Unlock()
			respondCeremonyError(w, r, 503, "Authentication state unavailable", "Request a fresh sign-in link.")
			return
		}
		state = sealed
	}
	authURL := oidcbroker.AuthorizeURL(conn, oidcbroker.AuthorizeParams{
		RedirectURI: redirectURI, State: state, Nonce: nonce, CodeChallenge: oidcbroker.CodeChallengeS256(verifier),
		MaxAgeSeconds: requestMaxAge, RequiredAMR: methods, ACRValues: requiredACR,
		LoginHint: safeAuthLoginHint(query.Get("login_hint")),
	})
	b.pending[state] = pa
	if requestID != "" {
		exp, _ := strconv.ParseInt(query.Get("expires_at"), 10, 64)
		b.ceremonies[requestID] = &authCeremony{tenant: tenant, device: boundDevice, state: state, authorizeURL: authURL, browserHash: browserHash, startExpires: time.Unix(exp, 0), expires: ceremonyDeadline, csrf: csrf, startQuery: query.Encode()}
	}
	b.mu.Unlock()
	navigateToAuthenticationProvider(w, r, authURL)
}

// handleCallback completes the flow: validate state, exchange the code, validate the ID token, mint a grant,
// set the grant cookie. Any failure denies (fail closed).
func (b *clientlessBroker) handleCallback(w http.ResponseWriter, r *http.Request) {
	authResponseHeaders(w)
	if !validAuthQuery(r) {
		respondCeremonyError(w, r, 400, "Invalid callback", "Restart authentication.")
		return
	}
	r = r.WithContext(captureCPWriteLease(r.Context()))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || ((code == "") == (r.URL.Query().Get("error") == "")) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing code/state"))
		return
	}
	pa, ok := b.takePending(r, state, time.Now().UTC())
	if !ok {
		pa, ok = b.recoverAuthState(r, state, time.Now().UTC())
	}
	if !ok || time.Since(pa.createdAt) > pendingAuthTTL {
		respondCeremonyError(w, r, http.StatusBadRequest, "Sign-in link expired",
			"This step-up link is no longer valid. Return to your terminal and start the connection again to get a fresh one.")
		return
	}
	defer b.endAuthCallback(state, pa.requestID)
	if code == "" {
		b.ceremonyError(w, r, pa, 401, "Authentication cancelled", "No authentication was granted.")
		return
	}
	// ★ THE SAME ORGANIZATION THE CEREMONY STARTED IN, carried in the pending state rather than re-read from
	// this node. A grant minted under the wrong organization satisfies nothing and is invisible: the gate
	// looks for it under the flow's organization and finds none, so the user authenticates and is held again.
	ceremonyTenant := strings.TrimSpace(pa.tenantID)
	if ceremonyTenant == "" {
		ceremonyTenant = b.tenantID
	}
	conn, ok := b.registry.Get(ceremonyTenant, pa.idpID)
	if !ok || authProviderDigest(conn) != pa.providerDigest {
		b.ceremonyError(w, r, pa, http.StatusBadRequest, "Sign-in unavailable",
			"The identity provider for this resource is no longer configured. Contact your administrator.")
		return
	}

	if b.checkTenantRegion != nil {
		if err := b.checkTenantRegion(r.Context(), ceremonyTenant); err != nil {
			b.ceremonyError(w, r, pa, http.StatusServiceUnavailable, "Authentication authority unavailable", "This organization cannot authenticate through this Edge Region.")
			return
		}
	}
	idToken, err := b.exchangeCode(conn, code, pa.redirectURI, pa.codeVerifier)
	if err != nil {
		// ★★★ THE PAGE SAID IT FAILED AND THE NODE SAID NOTHING (2026-09-03, measured: a step-up that got the
		// user all the way through the provider and then showed "Sign-in failed" — with not one line in the
		// Edge's log to say why). The reader of this page cannot act on it; the operator can, and had nothing.
		// The provider's own words are what distinguishes "wrong secret" from "cannot reach it" from "the code
		// was already used", and they were being discarded.
		log.Printf("clientless_exchange_failed idp=%q tenant=%q", conn.IdPID, ceremonyTenant)
		b.ceremonyError(w, r, pa, http.StatusBadGateway, "Sign-in failed",
			"We couldn't reach your identity provider to complete authentication. Please try again, or contact your administrator.")
		return
	}
	jwks, err := b.fetchJWKS(conn)
	if err != nil {
		log.Printf("clientless_jwks_failed idp=%q tenant=%q", conn.IdPID, ceremonyTenant)
		b.ceremonyError(w, r, pa, http.StatusBadGateway, "Sign-in failed",
			"We couldn't verify your identity provider's signing keys. Please try again, or contact your administrator.")
		return
	}
	id, err := oidcbroker.ValidateIDToken(conn, idToken, oidcbroker.ValidateOptions{
		JWKS: jwks, ExpectedNonce: pa.nonce, Now: time.Now().UTC(),
		RequiredACR: pa.requiredACR, RequiredAMR: pa.requiredAMR, MaxAgeSeconds: pa.maxAgeSeconds, AuthenticationStartedAt: pa.createdAt,
		AuthenticationNotBefore: pa.reauthenticateAfter,
	})
	if err != nil {
		log.Printf("clientless_identity_validation_failed idp=%q tenant=%q", conn.IdPID, ceremonyTenant)
		// Fail closed with a branded DENIED page (browser) — the common case is the assurance floor not being
		// met (e.g. only password when a phishing-resistant passkey is required). Do not leak the raw reason.
		detail := "We couldn't verify your identity for this resource. If you believe this is an error, contact your administrator."
		if strings.EqualFold(strings.TrimSpace(pa.requiredACR), "phishing_resistant") {
			detail = "This internal resource requires a phishing-resistant passkey, and your sign-in didn't provide one. Return to your terminal and try again with your passkey, or contact your administrator."
		}
		b.ceremonyError(w, r, pa, http.StatusUnauthorized, "Access denied", detail)
		return
	}

	grantID := ""
	if pa.requestID != "" {
		// The signed start request may be opened again on another Portal after a
		// restart. All fleet members must attempt the SAME opaque grant ID so the
		// shared authority's unique-key check rejects a second issuance. Never
		// use the browser-visible request ID itself as a bearer grant ID.
		grantID = b.signer.grantIDForRequest(pa.requestID)
		if grantID == "" {
			respondCeremonyError(w, r, 503, "Authentication signing unavailable", "Request a fresh link.")
			return
		}
	} else {
		var err error
		grantID, err = oidcbroker.NewOpaqueToken()
		if err != nil {
			writeError(w, 500, fmt.Errorf("generate grant identifier"))
			return
		}
	}
	userID := id.Subject // ValidateIDToken requires the stable, signed subject.
	// Refresh after identity verification. A revocation may have happened while
	// the browser was at the IdP; the authority mint checks once more atomically.
	currentBoundary, boundaryErr := b.reauthenticationBoundary(r.Context(), grantstore.Grant{TenantID: ceremonyTenant, UserID: userID, DeviceID: pa.boundDevice, OSPrincipal: pa.osPrincipal, IdPID: conn.IdPID, Issuer: conn.Issuer, Scope: federatedDestinationScope(pa.returnTo)})
	if boundaryErr != nil || oidcbroker.ValidateAuthenticationAfter(id.AuthTime, currentBoundary, time.Now().UTC()) != nil {
		b.ceremonyError(w, r, pa, 401, "Fresh sign-in required", "An administrator requires a new identity verification. Return to your app and start a fresh sign-in.")
		return
	}
	// Only the verified start request can bind a device. An anonymous/clientless
	// ceremony must not acquire device authority from whichever transport carries
	// its callback (which may differ from the one that initiated it).
	boundDevice := pa.boundDevice
	currentProvider, configured := b.registry.Get(ceremonyTenant, pa.idpID)
	if !configured || authProviderDigest(currentProvider) != pa.providerDigest || !time.Now().Before(pa.createdAt.Add(pendingAuthTTL)) {
		b.ceremonyError(w, r, pa, 401, "Authentication context changed", "Request a fresh link.")
		return
	}
	identityEnabled, identityKnown := b.rollout.deviceUserBindingMode()
	if boundDevice != "" && !identityKnown {
		b.ceremonyError(w, r, pa, 503, "Authentication upgrade state unavailable", "Request a fresh link when authentication services are available.")
		return
	}
	if boundDevice != "" && (identityEnabled || pa.osPrincipal != "") {
		binding, assigned := currentProvider.AssignedBinding(boundDevice, pa.osPrincipal)
		if !identityEnabled || !assigned || binding.Subject != id.Subject || binding.Revision != pa.bindingRevision || id.Issuer != currentProvider.Issuer || !validAuthOwner(pa.osPrincipal, pa.osSession) {
			b.ceremonyError(w, r, pa, 403, "This account cannot approve the request", "Sign in with the account assigned to the originating OS user, or contact your administrator.")
			return
		}
	}
	b.mu.Lock()
	if pa.requestID != "" {
		current := b.ceremonies[pa.requestID]
		if (!pa.recovered && (current == nil || current.state != state || !current.busy || !time.Now().Before(current.expires))) ||
			(pa.recovered && (current != nil && (current.state != state || current.succeeded))) {
			b.mu.Unlock()
			respondCeremonyError(w, r, 401, "Sign-in expired", "Request a fresh link.")
			return
		}
		if current != nil {
			current.succeeded = true // no retry after an ambiguous persistence outcome
		}
	}
	b.mu.Unlock()
	reauthenticatedAt := ""
	singleRequestID := ""
	if pa.maxAgeSeconds != nil && *pa.maxAgeSeconds == 0 {
		reauthenticatedAt = pa.createdAt.UTC().Format(time.RFC3339)
		singleRequestID = pa.requestID
		if singleRequestID == "" || boundDevice == "" {
			respondCeremonyError(w, r, 400, "Request-bound authentication required", "Start authentication from the application request.")
			return
		}
	}
	mintAt := time.Now().UTC()
	ttl := b.grantTTL
	if pa.grantTTLSeconds != nil {
		if !validAuthGrantTTLSeconds(*pa.grantTTLSeconds) {
			respondCeremonyError(w, r, 400, "Sign-in expired", "Request a fresh sign-in link.")
			return
		}
		if cap := time.Duration(*pa.grantTTLSeconds) * time.Second; cap < ttl {
			ttl = cap
		}
	}
	if singleRequestID != "" {
		if !b.rollout.featureEnabled("single-request-v1") {
			respondCeremonyError(w, r, 503, "Authentication upgrade state unavailable", "Request a fresh sign-in link after the deployment has confirmed its authentication capabilities.")
			return
		}
		if remaining := pa.deadline.Sub(mintAt); remaining < ttl {
			ttl = remaining
		}
		if ttl < time.Second {
			respondCeremonyError(w, r, 401, "Sign-in expired", "Request a fresh link.")
			return
		}
	}
	scope := federatedDestinationScope(pa.returnTo)
	if scope == "" {
		respondCeremonyError(w, r, 400, "Invalid authentication destination", "Start authentication from the application request.")
		return
	}
	grant, err := b.mintGrant(r.Context(), grantstore.Grant{
		GrantID: grantID, TenantID: ceremonyTenant, UserID: userID, IdPID: conn.IdPID,
		Issuer: id.Issuer, ProviderConfigSHA256: authEvidenceForOwner(conn, boundDevice, pa.osPrincipal, pa.osSession),
		OSPrincipal: pa.osPrincipal, OSSession: pa.osSession,
		ACR: id.ACR, AMR: id.AMR, AuthTime: id.AuthTime, DeviceID: boundDevice,
		ReauthenticationStartedAt: reauthenticatedAt, AuthenticationRequestID: singleRequestID,
		// Self-describing identity + scope: WHO was approved (from the verified ID token, not a
		// directory lookup) and WHAT destination the ceremony was started for (return_to, e.g.
		// "10.20.0.10:22"; informational — the gate itself matches identity × device × idp × acr).
		UserEmail: id.Email, Username: id.Username, UserDisplayName: id.DisplayName,
		Scope: scope,
	}, ttl, mintAt)
	if err != nil {
		respondCeremonyError(w, r, http.StatusServiceUnavailable, "Authentication result could not be saved", "Request a fresh link. Do not reuse this sign-in attempt.")
		return
	}
	if b.publishGrants != nil && !(b.authority != nil && b.rollout.featureEnabled(authrollout.RevocationReauthenticationFeature)) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		b.publishGrants(ctx)
		cancel()
	}
	http.SetCookie(w, &http.Cookie{
		Name: b.cookieName, Value: grant.GrantID, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	if pa.returnTo != "" {
		// Open-redirect guard: only redirect to a SAME-ORIGIN relative path (no `//`, no absolute/host URL),
		// the same check the first-party OIDC login uses. An unsafe return_to falls through to the JSON
		// response rather than bouncing the browser to an attacker-controlled URL.
		if safe, ok := sanitizeOIDCReturnTo(pa.returnTo); ok {
			http.Redirect(w, r, safe, http.StatusFound)
			return
		}
	}
	// A native TCP client's OOB step-up lands here with no safe browser return_to (return_to="host:22"). The
	// requester IS a browser, so render a branded success page — NOT the raw JSON grant (poor UX). API/test
	// callers that ask for JSON still get it.
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "authenticated", "grant_id": grant.GrantID, "identity": id,
		})
		return
	}
	writeCeremonySuccessHTML(w, id.Email, id.ACR, pa.returnTo, r)
}

// writeCeremonySuccessHTML confirms authentication, not access. The Edge still
// checks current policy before resuming a waiting connection.
func writeCeremonySuccessHTML(w http.ResponseWriter, email, acr, returnTo string, requests ...*http.Request) {
	evidence := "You verified with your identity."
	if strings.EqualFold(strings.TrimSpace(acr), "phishing_resistant") {
		evidence = "You verified with a phishing-resistant passkey."
	}
	dest := strings.TrimSpace(returnTo)
	destLine := ""
	if dest != "" {
		destLine = `<p class="dest">` + ceremonyLabel("Connecting to", requests...) + ` <code>` + html.EscapeString(dest) + `</code></p>`
	}
	body := `<p class="factor">` + ceremonyLabel(evidence, requests...) + `</p>
  ` + destLine + `
  <p class="hint">` + ceremonyLabel("Return to your app. A waiting connection resumes only if current policy permits it. If it has timed out, reconnect. You can close this tab.", requests...) + `</p>`
	footer := `<div class="who">` + ceremonyLabel("Signed in as", requests...) + ` <b>` + html.EscapeString(strings.TrimSpace(email)) + `</b></div>`
	page := ceremonyPageShell(
		`<div class="icon ok"><svg viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6.5"/></svg></div>`,
		"Authentication completed", body, footer, requests...)
	writeCeremonyPage(w, http.StatusOK, page)
}

// respondCeremonyError renders a branded DENIED/error page for a browser step-up, or JSON for API/test callers
// (Accept: application/json). Fail-closed messages only — never leak raw upstream/token error detail.
func respondCeremonyError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		writeError(w, status, fmt.Errorf("%s", detail))
		return
	}
	writeCeremonyDeniedHTML(w, status, title, detail, r)
}

// writeCeremonyDeniedHTML renders the branded "Access denied / sign-in failed" page (red state), same Console
// dark theme + shell as the success page.
func writeCeremonyDeniedHTML(w http.ResponseWriter, status int, title, detail string, requests ...*http.Request) {
	page := ceremonyPageShell(
		`<div class="icon deny"><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></div>`,
		html.EscapeString(title),
		`<p class="detail">`+ceremonyErrorLabel(detail, requests...)+`</p>`,
		"", requests...,
	)
	writeCeremonyPage(w, status, page)
}

// ceremonyPageShell wraps the state-specific icon/heading/body in the shared Console-themed card. The accent
// (green success / red deny) is driven by the icon's class, so both states share one stylesheet.
func ceremonyPageShell(iconHTML, heading, bodyHTML, footerHTML string, requests ...*http.Request) string {
	lang := ceremonyLanguage(requests...)
	plainHeading := html.UnescapeString(heading)
	translatedHeading := ceremonyTranslation(plainHeading, lang)
	if _, known := ceremonyJapanese[plainHeading]; !known && lang == "ja" {
		translatedHeading = ceremonyJapanese["Unable to complete request"]
	}
	return `<!doctype html><html lang="` + lang + `"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(translatedHeading) + ` — Lantern DSSE</title>
<style>
  :root{color-scheme:dark}*{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;
    color:#e6edf3;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .card{width:min(92vw,440px);background:#161b22;border:1px solid #30363d;border-radius:14px;
    padding:34px 34px 28px;box-shadow:0 12px 40px rgba(0,0,0,.45);text-align:center}
  .brand{display:flex;align-items:center;justify-content:center;gap:8px;color:#9da7b3;
    font-weight:600;letter-spacing:.02em;margin-bottom:22px}
  .brand .d{color:#58a6ff;font-size:18px}
  .language{display:flex;align-items:center;justify-content:center;gap:8px;font-size:12px;margin-bottom:18px;color:#adbac7}
  .language button{background:#21262d;color:#e6edf3;border:1px solid #484f58;border-radius:6px;padding:5px 10px;cursor:pointer}
  .language button[aria-pressed=true]{border-color:#58a6ff;color:#79c0ff}
  button:focus-visible,a:focus-visible{outline:2px solid #79c0ff;outline-offset:3px}
  form button{margin-top:18px;background:#238636;color:#fff;border:1px solid #2ea043;border-radius:6px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer}
  form button:hover{background:#2ea043}
  .icon{width:64px;height:64px;border-radius:50%;margin:0 auto 18px;display:grid;place-items:center}
  .icon svg{width:34px;height:34px;stroke-width:3;fill:none;stroke-linecap:round}
  .icon.ok{background:rgba(46,160,67,.15);border:1px solid rgba(46,160,67,.4)}
  .icon.ok svg{stroke:#3fb950}
  .icon.deny{background:rgba(248,81,73,.14);border:1px solid rgba(248,81,73,.4)}
  .icon.deny svg{stroke:#f85149}
  h1{font-size:20px;margin:0 0 8px}p{margin:6px 0;color:#adbac7}.factor{color:#e6edf3}.detail{color:#adbac7}
  .who{margin-top:18px;padding-top:16px;border-top:1px solid #21262d;font-size:13px;color:#8b949e}
  .who b{color:#c9d1d9;font-weight:600}.dest{margin-top:14px;font-size:13px}
  code{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:1px 6px;font-size:12px;color:#79c0ff}
  .hint{margin-top:20px;font-size:13px;color:#adbac7}
</style></head><body>
<div class="card">
  <div class="brand"><span class="d">◆</span> Lantern DSSE</div>
  <div class="language" role="group" aria-label="Language / 言語"><span>Language / 言語</span><button type="button" data-dsse-language="en" aria-pressed="` + strconv.FormatBool(lang == "en") + `">EN</button><button type="button" data-dsse-language="ja" aria-pressed="` + strconv.FormatBool(lang == "ja") + `">日本語</button></div>
  ` + iconHTML + `
  <h1 data-dsse-text="` + html.EscapeString(plainHeading) + `" data-dsse-fallback="Unable to complete request">` + html.EscapeString(translatedHeading) + `</h1>
  ` + bodyHTML + footerHTML + `
</div><script>` + ceremonyLanguageScript + `</script></body></html>`
}

// writeCeremonyPage emits a ceremony HTML page with the relaxed per-page CSP (the Edge default CSP's
// style-src 'self' would block the inline <style> -> unstyled render). Static, self-contained, no network.
func writeCeremonyPage(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Cache-Control", "no-store")
	if w.Header().Get("Referrer-Policy") == "" {
		w.Header().Set("Referrer-Policy", "no-referrer")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Accept-Language, Cookie")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'sha256-"+ceremonyLanguageScriptHash+"'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

// handleWhoami reports the identity behind the grant cookie when the grant is still live (for the protected
// resource to check). No cookie / revoked / expired grant => 401.
func (b *clientlessBroker) handleWhoami(w http.ResponseWriter, r *http.Request) {
	authResponseHeaders(w)
	c, err := r.Cookie(b.cookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("no grant"))
		return
	}
	g, exists := b.grants.GetForAuthorization(c.Value)
	expires, expiryErr := time.Parse(time.RFC3339, g.ExpiresAt)
	if !exists || g.Revoked || expiryErr != nil || !time.Now().Before(expires) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("grant is revoked or expired"))
		return
	}
	provider, configured := b.registry.Get(g.TenantID, g.IdPID)
	if !configured || ((g.Issuer != provider.Issuer || g.ProviderConfigSHA256 != authEvidenceForOwner(provider, g.DeviceID, g.OSPrincipal, g.OSSession)) && !b.rollout.acceptLegacy(g, authEvidenceProviderDigest(provider), time.Now())) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("authentication context changed"))
		return
	}
	identityEnabled, identityKnown := b.rollout.deviceUserBindingMode()
	if g.DeviceID != "" && !identityKnown {
		writeError(w, 503, fmt.Errorf("authentication upgrade state unavailable"))
		return
	}
	if g.DeviceID != "" && (identityEnabled || g.OSPrincipal != "") {
		subject, assigned := provider.AssignedSubject(g.DeviceID, g.OSPrincipal)
		if !identityEnabled || !assigned || subject != g.UserID || !validAuthOwner(g.OSPrincipal, g.OSSession) {
			writeError(w, 401, fmt.Errorf("device user assignment changed"))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "authenticated", "user_id": g.UserID, "idp_id": g.IdPID, "grant_id": g.GrantID})
}

func (b *clientlessBroker) exchangeCode(conn idpregistry.Connection, code, redirectURI, verifier string) (string, error) {
	form := oidcbroker.TokenRequestForm(conn, code, redirectURI, verifier)
	req, err := http.NewRequest(http.MethodPost, conn.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client, cerr := idpHTTPClient(b.httpClient, conn)
	if cerr != nil {
		return "", cerr
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(tr.IDToken) == "" {
		return "", fmt.Errorf("token response has no id_token")
	}
	return tr.IDToken, nil
}

func (b *clientlessBroker) fetchJWKS(conn idpregistry.Connection) (oidcbroker.JWKS, error) {
	if strings.TrimSpace(conn.JWKSURI) == "" {
		return oidcbroker.JWKS{}, fmt.Errorf("connection has no jwks_uri")
	}
	req, err := http.NewRequest(http.MethodGet, conn.JWKSURI, nil)
	if err != nil {
		return oidcbroker.JWKS{}, err
	}
	client, cerr := idpHTTPClient(b.httpClient, conn)
	if cerr != nil {
		return oidcbroker.JWKS{}, cerr
	}
	resp, err := client.Do(req)
	if err != nil {
		return oidcbroker.JWKS{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcbroker.JWKS{}, fmt.Errorf("jwks_uri returned %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return oidcbroker.ParseJWKS(data)
}

func authProviderDigest(conn idpregistry.Connection) [32]byte {
	// Assignments are checked against the authenticated subject again before
	// minting. An unrelated user's assignment edit must not invalidate an
	// already-running OIDC ceremony for this device and OS account.
	conn.DeviceUserBindings = nil
	data, _ := json.Marshal(conn)
	return sha256.Sum256(data)
}

// A login hint is UX input only; the signed ID token subject remains authoritative.
func safeAuthLoginHint(hint string) string {
	hint = strings.TrimSpace(hint)
	if len(hint) > 256 || strings.ContainsAny(hint, "\r\n\x00") {
		return ""
	}
	return hint
}
