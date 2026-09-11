package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
)

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type oidcValidatedClaims struct {
	Subject   string
	Email     string
	Groups    []string
	AMR       []string
	ACR       string
	AuthTime  string
	ExpiresAt string
	Raw       map[string]any
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

const oidcJWKSTTL = 5 * time.Minute

type oidcJWKSCacheEntry struct {
	jwks      jwksDocument
	expiresAt time.Time
}

type oidcCookieNames struct {
	State    string
	Nonce    string
	Verifier string
}

var userOIDCCookies = oidcCookieNames{State: "oidc_state", Nonce: "oidc_nonce", Verifier: "pkce_verifier"}
var adminOIDCCookies = oidcCookieNames{State: "admin_oidc_state", Nonce: "admin_oidc_nonce", Verifier: "admin_pkce_verifier"}

var oidcJWKSCache = struct {
	mu      sync.Mutex
	entries map[string]oidcJWKSCacheEntry
}{
	entries: map[string]oidcJWKSCacheEntry{},
}

func sessionFromOIDCCallback(r *http.Request, client *http.Client, config oidcConfig, store *sessionstore.Store, policyBundleID, tenantID string, now time.Time) (model.AuthenticationEvent, model.Session, error) {
	claims, err := claimsFromOIDCCallback(r, client, config, userOIDCCookies, now)
	if err != nil {
		return model.AuthenticationEvent{}, model.Session{}, err
	}
	event := authenticationEventFromOIDCClaims(config, claims, r, now, tenantID)
	session, err := store.CreateFromAuthenticationEvent(event, policyBundleID, tenantID, now)
	if err != nil {
		return model.AuthenticationEvent{}, model.Session{}, err
	}
	return event, session, nil
}

func claimsFromOIDCCallback(r *http.Request, client *http.Client, config oidcConfig, cookies oidcCookieNames, now time.Time) (oidcValidatedClaims, error) {
	if config.Issuer == "" || config.ClientID == "" || config.RedirectURI == "" {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC issuer, client_id, and redirect_uri are required")
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC authorization code is required")
	}
	stateCookie, err := r.Cookie(cookies.State)
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC state cookie is required")
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC state mismatch")
	}
	nonceCookie, err := r.Cookie(cookies.Nonce)
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC nonce cookie is required")
	}
	verifierCookie, err := r.Cookie(cookies.Verifier)
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC PKCE verifier cookie is required")
	}

	tokens, err := exchangeOIDCCode(r.Context(), client, config, code, verifierCookie.Value)
	if err != nil {
		return oidcValidatedClaims{}, err
	}
	claims, err := verifyOIDCIDToken(r.Context(), client, config, tokens.IDToken, nonceCookie.Value, now)
	if err != nil {
		return oidcValidatedClaims{}, err
	}
	return claims, nil
}

func exchangeOIDCCode(ctx context.Context, client *http.Client, config oidcConfig, code, verifier string) (oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", config.RedirectURI)
	if config.ClientSecret == "" {
		form.Set("client_id", config.ClientID)
	}
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcTokenEndpoint(config), strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if config.ClientSecret != "" {
		req.SetBasicAuth(config.ClientID, config.ClientSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcTokenResponse{}, fmt.Errorf("OIDC token endpoint returned status %d", resp.StatusCode)
	}
	var tokens oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return oidcTokenResponse{}, fmt.Errorf("decode OIDC token response: %w", err)
	}
	if tokens.IDToken == "" {
		return oidcTokenResponse{}, fmt.Errorf("OIDC id_token is required")
	}
	return tokens, nil
}

func verifyOIDCIDToken(ctx context.Context, client *http.Client, config oidcConfig, idToken, expectedNonce string, now time.Time) (oidcValidatedClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC id_token must be a signed JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("decode OIDC id_token header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("parse OIDC id_token header: %w", err)
	}
	if fmt.Sprint(header["alg"]) != "RS256" {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC id_token alg must be RS256")
	}
	key, err := oidcRSAPublicKey(ctx, client, config, fmt.Sprint(header["kid"]))
	if err != nil {
		return oidcValidatedClaims{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("decode OIDC id_token signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("verify OIDC id_token signature: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("decode OIDC id_token payload: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return oidcValidatedClaims{}, fmt.Errorf("parse OIDC id_token payload: %w", err)
	}
	if stringClaim(raw, "iss") != config.Issuer {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC issuer mismatch")
	}
	if !audienceContains(raw["aud"], config.ClientID) {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC audience mismatch")
	}
	exp, ok := int64Claim(raw, "exp")
	if !ok {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC exp claim is required")
	}
	if !now.Before(time.Unix(exp, 0)) {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC id_token is expired")
	}
	if stringClaim(raw, "nonce") != expectedNonce {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC nonce mismatch")
	}
	subject := stringClaim(raw, "sub")
	if subject == "" {
		return oidcValidatedClaims{}, fmt.Errorf("OIDC sub claim is required")
	}
	authTime := now.UTC().Format(time.RFC3339)
	if unixAuthTime, ok := int64Claim(raw, "auth_time"); ok {
		authTime = time.Unix(unixAuthTime, 0).UTC().Format(time.RFC3339)
	} else if value := stringClaim(raw, "auth_time"); value != "" {
		authTime = value
	}
	groups, err := oidcGroupsFromClaims(config, raw)
	if err != nil {
		return oidcValidatedClaims{}, err
	}
	return oidcValidatedClaims{
		Subject:   subject,
		Email:     stringClaim(raw, "email"),
		Groups:    groups,
		AMR:       stringArrayClaim(raw, "amr"),
		ACR:       stringClaim(raw, "acr"),
		AuthTime:  authTime,
		ExpiresAt: time.Unix(exp, 0).UTC().Format(time.RFC3339),
		Raw:       raw,
	}, nil
}

func oidcRSAPublicKey(ctx context.Context, client *http.Client, config oidcConfig, kid string) (*rsa.PublicKey, error) {
	now := time.Now().UTC()
	cacheKey := oidcJWKSURI(config)
	if jwks, ok := cachedOIDCJWKS(cacheKey, now); ok {
		key, found, err := rsaPublicKeyFromJWKS(jwks, kid)
		if err != nil {
			return nil, err
		}
		if found {
			return key, nil
		}
	}
	jwks, err := fetchOIDCJWKS(ctx, client, config)
	if err != nil {
		return nil, err
	}
	cacheOIDCJWKS(cacheKey, jwks, now.Add(oidcJWKSTTL))
	key, found, err := rsaPublicKeyFromJWKS(jwks, kid)
	if err != nil {
		return nil, err
	}
	if found {
		return key, nil
	}
	return nil, fmt.Errorf("OIDC JWKS signing key is absent")
}

func fetchOIDCJWKS(ctx context.Context, client *http.Client, config oidcConfig) (jwksDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oidcJWKSURI(config), nil)
	if err != nil {
		return jwksDocument{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return jwksDocument{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return jwksDocument{}, fmt.Errorf("OIDC JWKS endpoint returned status %d", resp.StatusCode)
	}
	var jwks jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return jwksDocument{}, fmt.Errorf("decode OIDC JWKS: %w", err)
	}
	return jwks, nil
}

func oidcAuthorizationEndpoint(config oidcConfig) string {
	if endpoint := strings.TrimSpace(config.AuthorizationEndpoint); endpoint != "" {
		return endpoint
	}
	return strings.TrimRight(config.Issuer, "/") + "/protocol/openid-connect/auth"
}

func oidcTokenEndpoint(config oidcConfig) string {
	if endpoint := strings.TrimSpace(config.TokenEndpoint); endpoint != "" {
		return endpoint
	}
	return strings.TrimRight(config.Issuer, "/") + "/protocol/openid-connect/token"
}

func oidcJWKSURI(config oidcConfig) string {
	if uri := strings.TrimSpace(config.JWKSURI); uri != "" {
		return uri
	}
	return strings.TrimRight(config.Issuer, "/") + "/protocol/openid-connect/certs"
}

func oidcGroupsFromClaims(config oidcConfig, raw map[string]any) ([]string, error) {
	groupsClaim := strings.TrimSpace(config.GroupsClaim)
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	groups := append([]string(nil), stringArrayClaim(raw, groupsClaim)...)
	hostedDomainClaim := strings.TrimSpace(config.HostedDomainClaim)
	if hostedDomainClaim == "" {
		return groups, nil
	}
	hostedDomain := strings.TrimSpace(stringClaim(raw, hostedDomainClaim))
	requiredHostedDomain := strings.TrimSpace(config.RequiredHostedDomain)
	if requiredHostedDomain != "" && hostedDomain != requiredHostedDomain {
		return nil, fmt.Errorf("OIDC hosted domain mismatch")
	}
	if hostedDomain == "" {
		return groups, nil
	}
	hostedDomainGroup := strings.TrimSpace(config.HostedDomainGroup)
	if hostedDomainGroup == "" {
		hostedDomainGroup = "/workspace/" + hostedDomain
	}
	if !stringSliceContains(groups, hostedDomainGroup) {
		groups = append(groups, hostedDomainGroup)
	}
	return groups, nil
}

func cachedOIDCJWKS(issuer string, now time.Time) (jwksDocument, bool) {
	oidcJWKSCache.mu.Lock()
	defer oidcJWKSCache.mu.Unlock()
	entry, ok := oidcJWKSCache.entries[issuer]
	if !ok || !now.Before(entry.expiresAt) {
		return jwksDocument{}, false
	}
	return entry.jwks, true
}

func cacheOIDCJWKS(issuer string, jwks jwksDocument, expiresAt time.Time) {
	oidcJWKSCache.mu.Lock()
	oidcJWKSCache.entries[issuer] = oidcJWKSCacheEntry{jwks: jwks, expiresAt: expiresAt}
	oidcJWKSCache.mu.Unlock()
}

func rsaPublicKeyFromJWKS(jwks jwksDocument, kid string) (*rsa.PublicKey, bool, error) {
	for _, key := range jwks.Keys {
		if key.KTY == "RSA" && (kid == "" || key.KID == kid) {
			publicKey, err := rsaPublicKeyFromJWK(key)
			return publicKey, true, err
		}
	}
	return nil, false, nil
}

func rsaPublicKeyFromJWK(key jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode JWK modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode JWK exponent: %w", err)
	}
	exponent := int(new(big.Int).SetBytes(eBytes).Int64())
	if exponent == 0 {
		return nil, fmt.Errorf("JWK exponent is invalid")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
}

func authenticationEventFromOIDCClaims(config oidcConfig, claims oidcValidatedClaims, r *http.Request, now time.Time, tenantID string) model.AuthenticationEvent {
	acr := claims.ACR
	sourceIP := sourceIPFromRequest(r)
	// Device binding is AUTHORITATIVE-or-absent (review #18): the callback URL's query is attacker-typed,
	// and a claimed device_id was baked into the trusted session, then flowed into decision requests
	// (session.DeviceID -> req.DeviceID) where device-scoped rules and grants match on it. Only a verified
	// (T) transport identity may bind the session to a device; a plain browser callback mints a
	// device-unbound session. (Device-bound step-up flows carry a SIGNED device via the broker instead.)
	deviceID := ""
	if id, verified := transportDeviceIdentityFromRequest(r); verified {
		deviceID = id
	}
	subjectUserID := claims.Subject
	event := model.AuthenticationEvent{
		ID:            randomEdgeID("auth_", now),
		TenantID:      tenantID,
		UserID:        claims.Subject,
		SubjectUserID: &subjectUserID,
		SessionID:     randomEdgeID("sess_", now),
		// The IdP id is operator config for THIS IdP — never the callback query (a claimed idp_id
		// satisfied required_idp_id step-up rules).
		IDPID:     valueOrDefault(config.IDPID, "idp_keycloak_lab"),
		Method:    "oidc_authorization_code",
		AMR:       claims.AMR,
		ACR:       &acr,
		MFAState:  mfaStateFromAMR(claims.AMR),
		AuthTime:  claims.AuthTime,
		ExpiresAt: &claims.ExpiresAt,
		SourceIP:  &sourceIP,
		Result:    "success",
		Timestamp: now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"issuer":    config.Issuer,
			"client_id": config.ClientID,
			"email":     claims.Email,
			"groups":    claims.Groups,
		},
	}
	if deviceID != "" {
		event.DeviceID = &deviceID
	}
	return event
}

func mfaStateFromAMR(amr []string) string {
	for _, value := range amr {
		switch value {
		case "otp", "totp", "sms", "mfa", "hwk":
			return "fresh"
		}
	}
	return "stale"
}

func audienceContains(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case []any:
		for _, item := range typed {
			if fmt.Sprint(item) == expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func int64Claim(values map[string]any, key string) (int64, bool) {
	value, ok := values[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringClaim(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func stringArrayClaim(values map[string]any, key string) []string {
	value, ok := values[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			items = append(items, fmt.Sprint(item))
		}
		return items
	case []string:
		return typed
	default:
		return nil
	}
}

const oidcReturnToCookieName = "oidc_return_to"

type oidcConfig struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	GroupsClaim           string
	HostedDomainClaim     string
	RequiredHostedDomain  string
	HostedDomainGroup     string
	// IDPID is the operator-configured identifier of THIS IdP, recorded on every session minted by the
	// callback (policy required_idp_id matches against it). It must never come from the callback request:
	// the callback URL is attacker-controllable, and a claimed idp_id satisfied step-up rules requiring a
	// specific IdP (review #18).
	IDPID string
}

func buildOIDCLoginURL(config oidcConfig) (string, []*http.Cookie, error) {
	return buildOIDCLoginURLWithCookies(config, userOIDCCookies)
}

func buildOIDCLoginURLWithCookies(config oidcConfig, cookieNames oidcCookieNames) (string, []*http.Cookie, error) {
	if config.Issuer == "" || config.ClientID == "" || config.RedirectURI == "" {
		return "", nil, fmt.Errorf("OIDC issuer, client_id, and redirect_uri are required")
	}
	state, err := randomURLToken(24)
	if err != nil {
		return "", nil, err
	}
	nonce, err := randomURLToken(24)
	if err != nil {
		return "", nil, err
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL, err := url.Parse(oidcAuthorizationEndpoint(config))
	if err != nil {
		return "", nil, err
	}
	values := authURL.Query()
	values.Set("response_type", "code")
	values.Set("client_id", config.ClientID)
	values.Set("redirect_uri", config.RedirectURI)
	values.Set("scope", "openid email profile")
	values.Set("state", state)
	values.Set("nonce", nonce)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	authURL.RawQuery = values.Encode()
	cookies := []*http.Cookie{
		oidcCookie(cookieNames.State, state),
		oidcCookie(cookieNames.Nonce, nonce),
		oidcCookie(cookieNames.Verifier, verifier),
	}
	return authURL.String(), cookies, nil
}

func oidcCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	}
}

func sessionCookie(session model.Session) *http.Cookie {
	return &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	}
}

func oidcReturnToCookie(returnTo string) *http.Cookie {
	return &http.Cookie{
		Name:     oidcReturnToCookieName,
		Value:    returnTo,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	}
}

// east-west OOB ceremony (E4): the challenge id is carried through the OIDC round-trip in a cookie, like
// return_to, so the callback can issue a grant against the held flow after the user authenticates.
const eastWestChallengeCookieName = "east_west_challenge"

func eastWestChallengeCookie(challengeID string) *http.Cookie {
	return &http.Cookie{
		Name:     eastWestChallengeCookieName,
		Value:    challengeID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	}
}

func expiredEastWestChallengeCookie() *http.Cookie {
	return expiredCookie(eastWestChallengeCookieName)
}

func expiredOIDCReturnToCookie() *http.Cookie {
	return expiredCookie(oidcReturnToCookieName)
}

func oidcReturnToFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(oidcReturnToCookieName)
	if err != nil {
		return "", false
	}
	return sanitizeOIDCReturnTo(cookie.Value)
}

func sanitizeOIDCReturnTo(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "", false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", false
	}
	return value, true
}

func expiredCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func decisionRequiresOIDCRedirect(decision string) bool {
	switch decision {
	case "require_reauthentication", "require_step_up_mfa", "require_interactive_mfa", "authenticate_required":
		return true
	default:
		return false
	}
}
