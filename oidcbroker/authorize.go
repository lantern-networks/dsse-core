// Package oidcbroker is the Edge's OIDC relying-party core for END-USER federated authentication: it builds
// the authorize redirect (auth code + PKCE), the token-exchange request, and — the security-critical part —
// validates the returned ID token (RS256 against the IdP's JWKS, issuer / audience / nonce / expiry, and the
// anti-cross-tenant domain check), returning the verified identity a policy decision can act on.
//
// It is pure logic + stdlib crypto (no network here): JWKS and the HTTP exchanges are passed in by the
// integration layer (the clientless front door / steered broker in a later slice), which keeps the
// security core unit-testable end to end. See docs/idp_federated_authentication_design.md.
package oidcbroker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
)

// AuthorizeParams are the per-flow values for an authorize redirect.
type AuthorizeParams struct {
	RedirectURI   string // the Edge callback URL (RP)
	Scope         string // e.g. "openid email profile"; "openid" is forced if absent
	State         string // CSRF token, echoed and checked on callback
	Nonce         string // replay token, must equal the ID token's nonce claim
	CodeChallenge string // PKCE S256 challenge (base64url of sha256(code_verifier))
	LoginHint     string // optional login_hint (e.g. the user's email)
	// ACRValues requests a stronger authentication context from the SAME IdP (OIDC step-up / RFC 9470): the
	// IdP must support the configured value; requesting a value is not proof that it was satisfied.
	// Entra uses an authentication context in the acrs claim, not an Authentication Strength ID.
	ACRValues     string
	MaxAgeSeconds *int64   // nil omits max_age; zero requests active reauthentication
	RequiredAMR   []string // request signed method information; validation still enforces every method
}

// AuthorizeURL builds the OIDC authorization-code + PKCE redirect to the connection's authorization endpoint.
func AuthorizeURL(conn idpregistry.Connection, p AuthorizeParams) string {
	scope := strings.TrimSpace(p.Scope)
	if scope == "" {
		scope = "openid email profile"
	} else if !strings.Contains(" "+scope+" ", " openid ") {
		scope = "openid " + scope
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", conn.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", scope)
	q.Set("state", p.State)
	q.Set("nonce", p.Nonce)
	if p.CodeChallenge != "" {
		q.Set("code_challenge", p.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	if strings.TrimSpace(p.LoginHint) != "" {
		q.Set("login_hint", strings.TrimSpace(p.LoginHint))
	}
	if strings.TrimSpace(p.ACRValues) != "" && conn.Type != "entra" {
		q.Set("acr_values", strings.TrimSpace(p.ACRValues)) // OIDC step-up: ask the SAME IdP for a stronger context
	}
	if p.MaxAgeSeconds != nil && conn.Type != "google" {
		q.Set("max_age", strconv.FormatInt(*p.MaxAgeSeconds, 10))
	}
	claims := map[string]any{}
	if conn.Type == "entra" && strings.TrimSpace(p.ACRValues) != "" {
		claims["acrs"] = map[string]any{"essential": true, "value": strings.TrimSpace(p.ACRValues)}
	}
	if p.MaxAgeSeconds != nil {
		claims["auth_time"] = map[string]any{"essential": true}
	}
	if len(p.RequiredAMR) > 0 {
		claims[firstNonBlank(conn.AMRClaim, "amr")] = map[string]any{"essential": true}
	}
	if len(claims) > 0 {
		encoded, _ := json.Marshal(map[string]any{"id_token": claims})
		q.Set("claims", string(encoded))
	}
	// Google enforces the hosted domain at the IdP too when hd is hinted.
	if conn.DomainMode == "google_hd" && len(conn.VerifiedDomains) == 1 {
		q.Set("hd", conn.VerifiedDomains[0])
	}
	sep := "?"
	if strings.Contains(conn.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return conn.AuthorizationEndpoint + sep + q.Encode()
}

// TokenRequestForm builds the form body for the authorization-code token exchange (the integration layer
// POSTs it to conn.TokenEndpoint with the client credential / PKCE verifier).
func TokenRequestForm(conn idpregistry.Connection, code, redirectURI, codeVerifier string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", conn.ClientID)
	if conn.ClientSecret != "" {
		form.Set("client_secret", conn.ClientSecret)
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	return form
}

// --- PKCE + opaque token helpers (crypto/rand) ----------------------------------------------------------

// NewCodeVerifier returns a high-entropy PKCE code_verifier (RFC 7636: 43-128 unreserved chars).
func NewCodeVerifier() (string, error) { return randomURLToken(32) }

// CodeChallengeS256 returns base64url(sha256(verifier)) — the S256 PKCE challenge.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewOpaqueToken returns a random base64url token for state / nonce / grant ids.
func NewOpaqueToken() (string, error) { return randomURLToken(24) }

func randomURLToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateAuthorizeParams rejects requirements the selected request mechanism cannot express.
// This is a safety gate, not a declaration of full provider compatibility.
func ValidateAuthorizeParams(conn idpregistry.Connection, p AuthorizeParams) error {
	if p.MaxAgeSeconds != nil && (*p.MaxAgeSeconds < 0 || *p.MaxAgeSeconds > 86400) {
		return fmt.Errorf("invalid maximum authentication age")
	}
	if conn.Type == "google" && (strings.TrimSpace(p.ACRValues) != "" || (p.MaxAgeSeconds != nil && *p.MaxAgeSeconds == 0)) {
		return fmt.Errorf("Google does not support requesting account reauthentication or an ACR; an additional verified authentication method is required")
	}
	// A positive Google age bound can be verified against a returned auth_time,
	// but cannot force Google to refresh it. Missing/stale claims still fail token
	// validation; do not send an unsupported max_age or loop ordinary SSO.
	if conn.Type == "entra" && p.ACRValues != "" {
		// Contexts are tenant-authored c1..c99. Their CA policy meaning must be configured by the operator.
		n, err := strconv.Atoi(strings.TrimPrefix(p.ACRValues, "c"))
		if err != nil || n < 1 || n > 99 || p.ACRValues != "c"+strconv.Itoa(n) {
			return fmt.Errorf("Entra requires a tenant authentication context c1..c99")
		}
		if conn.ACRClaim != "" && conn.ACRClaim != "acrs" {
			return fmt.Errorf("Entra authentication contexts must be validated using acrs")
		}
	}
	return nil
}
