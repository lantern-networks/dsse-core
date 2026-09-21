package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
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
	registry    *idpregistry.Store
	grants      *grantstore.Store
	httpClient  *http.Client
	selfBaseURL string // e.g. https://edge:8443 — used to build the RP redirect_uri
	tenantID    string
	grantTTL    time.Duration
	cookieName  string
	signer      *deviceBindingSigner // verifies the device the gate signed into the start URL (per-device grants)

	mu      sync.Mutex
	pending map[string]pendingAuth
}

type pendingAuth struct {
	idpID        string
	nonce        string
	codeVerifier string
	redirectURI  string
	returnTo     string
	requiredACR  string
	requiredAMR  []string
	boundDevice  string // the verified (T) device the gate signed into the start URL; "" = tenant-wide grant
	tenantID     string // the organization the held flow belonged to, signed into the start URL beside the device
	createdAt    time.Time
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
		cookieName: "dsse_grant", signer: signer, pending: map[string]pendingAuth{},
	}
}

func (b *clientlessBroker) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /clientless/auth/start", b.handleStart)
	mux.HandleFunc("GET /clientless/auth/callback", b.handleCallback)
	mux.HandleFunc("GET /clientless/auth/whoami", b.handleWhoami)
}

// handleStart redirects the browser to the required IdP (auth code + PKCE). ?idp= selects a registered IdP
// (else the tenant default); ?return_to= is where to land after success.
func (b *clientlessBroker) handleStart(w http.ResponseWriter, r *http.Request) {
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
	boundDevice, tenant := b.signer.verifiedBinding(
		r.URL.Query().Get("device"), r.URL.Query().Get("tenant"), r.URL.Query().Get("device_sig"))
	if tenant == "" {
		tenant = b.tenantID
	}
	conn, ok := b.registry.Resolve(tenant, idp)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no usable IdP for organization %q (required %q is not registered)", tenant, idp))
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
	// Per-device binding: verified above, together with the organization. An unsigned or forged value yields
	// no device, so the grant is tenant-wide rather than mis-bound.
	b.mu.Lock()
	b.pending[state] = pendingAuth{
		idpID: conn.IdPID, nonce: nonce, codeVerifier: verifier, redirectURI: redirectURI, requiredACR: requiredACR,
		returnTo: strings.TrimSpace(r.URL.Query().Get("return_to")), boundDevice: boundDevice,
		tenantID: tenant, createdAt: time.Now().UTC(),
	}
	b.mu.Unlock()
	authURL := oidcbroker.AuthorizeURL(conn, oidcbroker.AuthorizeParams{
		RedirectURI: redirectURI, State: state, Nonce: nonce, CodeChallenge: oidcbroker.CodeChallengeS256(verifier),
		LoginHint: strings.TrimSpace(r.URL.Query().Get("login_hint")), ACRValues: requiredACR,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback completes the flow: validate state, exchange the code, validate the ID token, mint a grant,
// set the grant cookie. Any failure denies (fail closed).
func (b *clientlessBroker) handleCallback(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(captureCPWriteLease(r.Context()))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("missing code/state"))
		return
	}
	b.mu.Lock()
	pa, ok := b.pending[state]
	delete(b.pending, state) // one-time use
	b.mu.Unlock()
	if !ok || time.Since(pa.createdAt) > pendingAuthTTL {
		respondCeremonyError(w, r, http.StatusBadRequest, "Sign-in link expired",
			"This step-up link is no longer valid. Return to your terminal and start the connection again to get a fresh one.")
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
	if !ok {
		respondCeremonyError(w, r, http.StatusBadRequest, "Sign-in unavailable",
			"The identity provider for this resource is no longer configured. Contact your administrator.")
		return
	}

	idToken, err := b.exchangeCode(conn, code, pa.redirectURI, pa.codeVerifier)
	if err != nil {
		// ★★★ THE PAGE SAID IT FAILED AND THE NODE SAID NOTHING (2026-09-03, measured: a step-up that got the
		// user all the way through the provider and then showed "Sign-in failed" — with not one line in the
		// Edge's log to say why). The reader of this page cannot act on it; the operator can, and had nothing.
		// The provider's own words are what distinguishes "wrong secret" from "cannot reach it" from "the code
		// was already used", and they were being discarded.
		log.Printf("clientless_exchange_failed idp=%q tenant=%q token_endpoint=%q: %v — the browser was shown "+
			"\"we couldn't reach your identity provider\"", conn.IdPID, ceremonyTenant, conn.TokenEndpoint, err)
		respondCeremonyError(w, r, http.StatusBadGateway, "Sign-in failed",
			"We couldn't reach your identity provider to complete authentication. Please try again, or contact your administrator.")
		return
	}
	jwks, err := b.fetchJWKS(conn)
	if err != nil {
		log.Printf("clientless_jwks_failed idp=%q tenant=%q jwks_uri=%q: %v", conn.IdPID, ceremonyTenant, conn.JWKSURI, err)
		respondCeremonyError(w, r, http.StatusBadGateway, "Sign-in failed",
			"We couldn't verify your identity provider's signing keys. Please try again, or contact your administrator.")
		return
	}
	id, err := oidcbroker.ValidateIDToken(conn, idToken, oidcbroker.ValidateOptions{
		JWKS: jwks, ExpectedNonce: pa.nonce, Now: time.Now().UTC(),
		RequiredACR: pa.requiredACR, RequiredAMR: pa.requiredAMR,
	})
	if err != nil {
		// Fail closed with a branded DENIED page (browser) — the common case is the assurance floor not being
		// met (e.g. only password when a phishing-resistant passkey is required). Do not leak the raw reason.
		detail := "We couldn't verify your identity for this resource. If you believe this is an error, contact your administrator."
		if strings.EqualFold(strings.TrimSpace(pa.requiredACR), "phishing_resistant") {
			detail = "This internal resource requires a phishing-resistant passkey, and your sign-in didn't provide one. Return to your terminal and try again with your passkey, or contact your administrator."
		}
		respondCeremonyError(w, r, http.StatusUnauthorized, "Access denied", detail)
		return
	}

	grantID, _ := oidcbroker.NewOpaqueToken()
	userID := id.Subject
	if userID == "" {
		userID = id.Email
	}
	// Bind the grant to the steered DEVICE: the device the gate signed into the start URL (carried in pending),
	// or the in-process (T) context when the broker IS reached over the decrypt path. Empty for a direct
	// clientless browser with no agent — a tenant/user grant. The steered-path gate then allows only this
	// device's flows.
	boundDevice := pa.boundDevice
	if boundDevice == "" {
		boundDevice = edgeplane.TransportDeviceFromContext(r.Context())
	}
	grant, err := b.grants.MintContext(r.Context(), grantstore.Grant{
		GrantID: grantID, TenantID: ceremonyTenant, UserID: userID, IdPID: conn.IdPID,
		ACR: id.ACR, AMR: id.AMR, DeviceID: boundDevice,
		// Self-describing identity + scope: WHO was approved (from the verified ID token, not a
		// directory lookup) and WHAT destination the ceremony was started for (return_to, e.g.
		// "10.20.0.10:22"; informational — the gate itself matches identity × device × idp × acr).
		UserEmail: id.Email, Username: id.Username, UserDisplayName: id.DisplayName,
		Scope: pa.returnTo,
	}, b.grantTTL, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("mint grant: %w", err))
		return
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
	writeCeremonySuccessHTML(w, id.Email, id.ACR, pa.returnTo)
}

// writeCeremonySuccessHTML renders the branded "authentication successful" page shown after an OOB East-West
// step-up completes. The connection auto-releases on the Edge (task #5), so the copy tells the operator to
// return to their terminal — nothing else to do. Self-contained (inline CSS), Console dark theme.
func writeCeremonySuccessHTML(w http.ResponseWriter, email, acr, returnTo string) {
	factor := "your identity"
	if strings.EqualFold(strings.TrimSpace(acr), "phishing_resistant") {
		factor = "a phishing-resistant passkey"
	}
	dest := strings.TrimSpace(returnTo)
	destLine := ""
	if dest != "" {
		destLine = `<p class="dest">Connecting to <code>` + html.EscapeString(dest) + `</code></p>`
	}
	body := `<p>You verified with <span class="factor">` + factor + `</span>.</p>
  ` + destLine + `
  <p class="hint">Return to your terminal — your connection is opening automatically. You can close this tab.</p>`
	footer := `<div class="who">Signed in as <b>` + html.EscapeString(strings.TrimSpace(email)) + `</b></div>`
	page := ceremonyPageShell(
		`<div class="icon ok"><svg viewBox="0 0 24 24"><path d="M4 12.5l5 5L20 6.5"/></svg></div>`,
		"Access approved", body, footer)
	writeCeremonyPage(w, http.StatusOK, page)
}

// respondCeremonyError renders a branded DENIED/error page for a browser step-up, or JSON for API/test callers
// (Accept: application/json). Fail-closed messages only — never leak raw upstream/token error detail.
func respondCeremonyError(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		writeError(w, status, fmt.Errorf("%s", detail))
		return
	}
	writeCeremonyDeniedHTML(w, status, title, detail)
}

// writeCeremonyDeniedHTML renders the branded "Access denied / sign-in failed" page (red state), same Console
// dark theme + shell as the success page.
func writeCeremonyDeniedHTML(w http.ResponseWriter, status int, title, detail string) {
	page := ceremonyPageShell(
		`<div class="icon deny"><svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg></div>`,
		html.EscapeString(title),
		`<p class="detail">`+html.EscapeString(detail)+`</p>`,
		"",
	)
	writeCeremonyPage(w, status, page)
}

// ceremonyPageShell wraps the state-specific icon/heading/body in the shared Console-themed card. The accent
// (green success / red deny) is driven by the icon's class, so both states share one stylesheet.
func ceremonyPageShell(iconHTML, heading, bodyHTML, footerHTML string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + heading + ` — Lantern DSSE</title>
<style>
  :root{color-scheme:dark}*{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;
    color:#e6edf3;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .card{width:min(92vw,440px);background:#161b22;border:1px solid #30363d;border-radius:14px;
    padding:34px 34px 28px;box-shadow:0 12px 40px rgba(0,0,0,.45);text-align:center}
  .brand{display:flex;align-items:center;justify-content:center;gap:8px;color:#9da7b3;
    font-weight:600;letter-spacing:.02em;margin-bottom:22px}
  .brand .d{color:#58a6ff;font-size:18px}
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
  .hint{margin-top:20px;font-size:13px;color:#6e7681}
</style></head><body>
<div class="card">
  <div class="brand"><span class="d">◆</span> Lantern DSSE</div>
  ` + iconHTML + `
  <h1>` + heading + `</h1>
  ` + bodyHTML + footerHTML + `
</div></body></html>`
}

// writeCeremonyPage emits a ceremony HTML page with the relaxed per-page CSP (the Edge default CSP's
// style-src 'self' would block the inline <style> -> unstyled render). Static, self-contained, no network.
func writeCeremonyPage(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

// handleWhoami reports the identity behind the grant cookie when the grant is still live (for the protected
// resource to check). No cookie / revoked / expired grant => 401.
func (b *clientlessBroker) handleWhoami(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(b.cookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("no grant"))
		return
	}
	if !b.grants.Valid(c.Value, time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("grant is revoked or expired"))
		return
	}
	g, _ := b.grants.Get(c.Value)
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
