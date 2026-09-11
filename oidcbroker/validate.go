package oidcbroker

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
)

// Identity is the verified end-user identity extracted from a valid ID token.
type Identity struct {
	IdPID         string   `json:"idp_id"`
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`         // the id token's email_verified claim (anti-spoof gate for the email-domain check)
	Username      string   `json:"username,omitempty"`     // preferred_username (profile scope)
	DisplayName   string   `json:"display_name,omitempty"` // name (profile scope)
	HostedDomain  string   `json:"hosted_domain,omitempty"`
	ACR           string   `json:"acr,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// ValidateOptions carry the per-flow expectations + the IdP's keys for ID-token validation.
type ValidateOptions struct {
	JWKS             JWKS
	ExpectedNonce    string        // must equal the token nonce (required when set)
	ExpectedAudience string        // must be in aud; defaults to conn.ClientID
	Now              time.Time     // defaults to time.Now().UTC()
	ClockSkew        time.Duration // tolerance for exp/nbf; defaults to 60s
	RequiredACR      string        // optional: token acr must equal this
	RequiredAMR      []string      // optional: token amr must include all of these
}

// ValidateIDToken verifies an OIDC ID token end to end and returns the identity it asserts. It enforces
// RS256 signature (against the connection's JWKS), issuer == conn.Issuer, audience, nonce, expiry, the
// anti-cross-tenant domain check (hd / email domain ∈ conn.VerifiedDomains), and any required acr/amr. Any
// failure returns an error (the caller fails closed — never allow on a validation error).
func ValidateIDToken(conn idpregistry.Connection, raw string, opts ValidateOptions) (Identity, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 60 * time.Second
	}
	aud := strings.TrimSpace(opts.ExpectedAudience)
	if aud == "" {
		aud = conn.ClientID
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("id token is not a JWS (want 3 segments)")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return Identity{}, fmt.Errorf("id token header: %w", err)
	}
	if header.Alg != "RS256" {
		return Identity{}, fmt.Errorf("id token alg %q is not allowed (want RS256)", header.Alg)
	}
	pub, err := opts.JWKS.keyByKID(header.Kid)
	if err != nil {
		return Identity{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("id token signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Identity{}, fmt.Errorf("id token signature is invalid")
	}

	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Identity{}, fmt.Errorf("id token claims: %w", err)
	}

	if iss := claimString(claims, "iss"); iss != strings.TrimSpace(conn.Issuer) {
		return Identity{}, fmt.Errorf("id token issuer %q does not match the registered IdP", iss)
	}
	if !audienceContains(claims["aud"], aud) {
		return Identity{}, fmt.Errorf("id token audience does not include %q", aud)
	}
	if opts.ExpectedNonce != "" && claimString(claims, "nonce") != opts.ExpectedNonce {
		return Identity{}, fmt.Errorf("id token nonce mismatch")
	}
	if exp, ok := claimTime(claims, "exp"); !ok || now.After(exp.Add(skew)) {
		return Identity{}, fmt.Errorf("id token is expired or missing exp")
	}
	if nbf, ok := claimTime(claims, "nbf"); ok && now.Add(skew).Before(nbf) {
		return Identity{}, fmt.Errorf("id token is not yet valid (nbf)")
	}

	// Assurance claim names are configurable (conn.ACRClaim/AMRClaim), like hd/groups. The acr claim is read
	// as a list so an IdP that carries assurance as an array (e.g. Entra Conditional Access "acrs") works as
	// well as a scalar acr (Okta/Google); acr is a representative scalar for display + the grant.
	acrClaim := firstNonBlank(conn.ACRClaim, "acr")
	acrList := claimStringList(claims, acrClaim)
	acr := claimString(claims, acrClaim)
	if acr == "" && len(acrList) > 0 {
		acr = acrList[0]
	}
	id := Identity{
		IdPID:         conn.IdPID,
		Issuer:        claimString(claims, "iss"),
		Subject:       claimString(claims, "sub"),
		Email:         claimString(claims, "email"),
		EmailVerified: claimBool(claims, "email_verified"),
		Username:      claimString(claims, "preferred_username"),
		DisplayName:   claimString(claims, "name"),
		HostedDomain:  claimString(claims, firstNonBlank(conn.HostedDomainClaim, "hd")),
		ACR:           acr,
		AMR:           claimStringList(claims, firstNonBlank(conn.AMRClaim, "amr")),
		Groups:        claimStringList(claims, firstNonBlank(conn.GroupsClaim, "groups")),
	}

	if err := enforceDomain(conn, id); err != nil {
		return Identity{}, err
	}
	// Required step-up acr: the acr claim must equal the requirement, or — when assurance is array-valued
	// (e.g. Entra acrs) — contain it. On success the satisfied value is recorded as the acr so a grant minted
	// from this identity matches an acr-gated resource exactly.
	if opts.RequiredACR != "" {
		if id.ACR != opts.RequiredACR && !containsString(acrList, opts.RequiredACR) {
			return Identity{}, fmt.Errorf("id token acr %q does not satisfy required %q", id.ACR, opts.RequiredACR)
		}
		id.ACR = opts.RequiredACR
	}
	for _, want := range opts.RequiredAMR {
		if !containsString(id.AMR, want) {
			return Identity{}, fmt.Errorf("id token amr is missing required method %q", want)
		}
	}
	return id, nil
}

// enforceDomain is the anti-cross-tenant check: the identity's domain must be one of the connection's
// verified domains.
//
// FAIL CLOSED on empty VerifiedDomains (review #23): a connection has a DomainMode (always set — normalize
// defaults it), so the operator ALWAYS intends the domain boundary. An empty verified-domains list means the
// anti-cross-tenant guard cannot run, and in a multi-tenant broker ([[multi-tenant-is-the-premise]])
// silently allowing every domain is a cross-tenant hole. Surface it as a config error rather than skip.
func enforceDomain(conn idpregistry.Connection, id Identity) error {
	if len(conn.VerifiedDomains) == 0 {
		return fmt.Errorf("idp connection has no verified_domains configured — the anti-cross-tenant domain check cannot run (fail closed)")
	}
	var domain string
	if conn.DomainMode == "google_hd" {
		domain = strings.ToLower(strings.TrimSpace(id.HostedDomain))
		if domain == "" {
			return fmt.Errorf("id token is missing the hosted-domain (hd) claim required by domain_mode=google_hd")
		}
	} else {
		// The email-domain check trusts the email's domain, so the email must be PROVEN: an unverified (or
		// absent) email_verified claim lets an IdP that permits arbitrary/unverified email addresses assert an
		// address in the victim tenant's domain and cross the boundary (review #23). Require email_verified.
		if !id.EmailVerified {
			return fmt.Errorf("id token email is not verified (email_verified) — required for the email-domain cross-tenant check")
		}
		at := strings.LastIndex(id.Email, "@")
		if at < 0 {
			return fmt.Errorf("id token email %q has no domain", id.Email)
		}
		domain = strings.ToLower(strings.TrimSpace(id.Email[at+1:]))
	}
	for _, d := range conn.VerifiedDomains {
		if domain == d {
			return nil
		}
	}
	return fmt.Errorf("id token domain %q is not one of the tenant's verified domains (cross-tenant)", domain)
}

// --- claim helpers ----------------------------------------------------------

func decodeSegment(seg string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimBool reads a boolean claim. Some IdPs serialize email_verified as a JSON string ("true") rather than
// a bool, so both are accepted; anything else is false (fail closed for a gate claim).
func claimBool(claims map[string]any, key string) bool {
	switch v := claims[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func claimStringList(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func claimTime(claims map[string]any, key string) (time.Time, bool) {
	switch v := claims[key].(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), true
	case int64:
		return time.Unix(v, 0).UTC(), true
	}
	return time.Time{}, false
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
