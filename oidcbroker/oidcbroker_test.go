package oidcbroker

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
)

const testKID = "test-key-1"

func testKeyAndJWKS(t *testing.T) (*rsa.PrivateKey, JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	eBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(eBuf, uint64(key.E))
	i := 0
	for i < len(eBuf)-1 && eBuf[i] == 0 {
		i++
	}
	jwk := JWK{Kty: "RSA", Kid: testKID, Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBuf[i:]),
	}
	return key, JWKS{Keys: []JWK{jwk}}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": testKID})
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func sampleConn() idpregistry.Connection {
	return idpregistry.Connection{
		IdPID: "idp_corp", TenantID: "t1", Type: "oidc",
		Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize",
		ClientID: "client-1", VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain",
	}
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://idp.example.com", "aud": "client-1", "sub": "user-1",
		"email": "alice@example.com", "email_verified": true, "preferred_username": "alice", "name": "Alice Example",
		"nonce": "NONCE", "exp": now.Add(time.Hour).Unix(),
		"acr": "AAL2", "amr": []any{"pwd", "mfa"},
	}
}

func TestValidateHappyPath(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()
	tok := signJWT(t, key, baseClaims(now))
	id, err := ValidateIDToken(sampleConn(), tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now})
	if err != nil {
		t.Fatalf("happy path should validate: %v", err)
	}
	if id.Subject != "user-1" || id.Email != "alice@example.com" || id.ACR != "AAL2" {
		t.Fatalf("identity not extracted: %+v", id)
	}
	if id.Username != "alice" || id.DisplayName != "Alice Example" {
		t.Fatalf("profile claims (preferred_username/name) not extracted: %+v", id)
	}
	if len(id.AMR) != 2 || id.AMR[0] != "pwd" {
		t.Fatalf("amr not extracted: %+v", id.AMR)
	}
}

func TestValidateRejections(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()
	conn := sampleConn()
	opts := func() ValidateOptions { return ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now} }

	// tampered signature
	tok := signJWT(t, key, baseClaims(now))
	tampered := tok[:len(tok)-2] + flip(tok[len(tok)-2:])
	if _, err := ValidateIDToken(conn, tampered, opts()); err == nil {
		t.Fatal("tampered signature must fail")
	}
	// wrong issuer
	c := baseClaims(now)
	c["iss"] = "https://evil.example.com"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("wrong issuer must fail")
	}
	// wrong audience
	c = baseClaims(now)
	c["aud"] = "client-2"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("wrong audience must fail")
	}
	// bad nonce
	c = baseClaims(now)
	c["nonce"] = "WRONG"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("nonce mismatch must fail")
	}
	// expired
	c = baseClaims(now)
	c["exp"] = now.Add(-time.Hour).Unix()
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("expired token must fail")
	}
	// cross-tenant domain (email domain not in verified domains)
	c = baseClaims(now)
	c["email"] = "bob@evil.com"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("cross-tenant email domain must fail")
	}
	// review #23: an in-domain email that is NOT verified must fail (an IdP allowing arbitrary/unverified
	// emails could otherwise assert a victim-tenant address).
	c = baseClaims(now)
	c["email_verified"] = false
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("unverified email must fail the email-domain check")
	}
	// review #23: missing email_verified entirely is also rejected (fail closed).
	c = baseClaims(now)
	delete(c, "email_verified")
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), opts()); err == nil {
		t.Fatal("missing email_verified must fail the email-domain check")
	}
	// review #23: an empty verified_domains list fails closed (the anti-cross-tenant guard cannot run).
	emptyDomains := sampleConn()
	emptyDomains.VerifiedDomains = nil
	if _, err := ValidateIDToken(emptyDomains, signJWT(t, key, baseClaims(now)), opts()); err == nil {
		t.Fatal("empty verified_domains must fail closed")
	}
	// alg none must be rejected
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"`+testKID+`"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(mustJSON(baseClaims(now))) + "."
	if _, err := ValidateIDToken(conn, none, opts()); err == nil {
		t.Fatal("alg=none must be rejected")
	}
	// signed by a DIFFERENT key must fail
	otherKey, _ := testKeyAndJWKS(t)
	if _, err := ValidateIDToken(conn, signJWT(t, otherKey, baseClaims(now)), opts()); err == nil {
		t.Fatal("token signed by an unknown key must fail")
	}
}

func TestValidateGoogleHostedDomain(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()
	conn := sampleConn()
	conn.Type = "google"
	conn.DomainMode = "google_hd"
	// missing hd -> fail
	if _, err := ValidateIDToken(conn, signJWT(t, key, baseClaims(now)), ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now}); err == nil {
		t.Fatal("google_hd without hd claim must fail")
	}
	// hd in verified domains -> ok
	c := baseClaims(now)
	c["hd"] = "example.com"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now}); err != nil {
		t.Fatalf("google_hd with a matching hd must validate: %v", err)
	}
	// hd of the wrong org -> fail
	c["hd"] = "evil.com"
	if _, err := ValidateIDToken(conn, signJWT(t, key, c), ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now}); err == nil {
		t.Fatal("google_hd with a non-verified hd must fail")
	}
}

// Review #23: a network-fed JWKS with an oversize RSA exponent must be REJECTED, not panic. The old
// left-pad `copy(padded[8-len(eBytes):], ...)` made a negative slice index for exponents longer than 8
// bytes — a slice-bounds panic that crashes the process on a hostile/corrupt key.
func TestJWKRejectsOversizeExponentWithoutPanic(t *testing.T) {
	// 9-byte exponent (one byte past the uint64 window) — previously a panic.
	jwk := JWK{Kty: "RSA", Kid: "k", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1})}
	if _, err := jwk.rsaPublicKey(); err == nil {
		t.Fatal("oversize exponent must be rejected")
	}
	// An 8-byte exponent whose value overflows a positive int must also be rejected (not wrap negative).
	huge := JWK{Kty: "RSA", Kid: "k", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		E: base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0, 0, 0, 0, 0, 0, 1})}
	if _, err := huge.rsaPublicKey(); err == nil {
		t.Fatal("out-of-range exponent must be rejected")
	}
	// A normal exponent (65537 = 0x010001) still parses.
	ok := JWK{Kty: "RSA", Kid: "k", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		E: base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})}
	if _, err := ok.rsaPublicKey(); err != nil {
		t.Fatalf("standard exponent must parse: %v", err)
	}
}

func TestValidateAssuranceRequirements(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()
	conn := sampleConn()
	tok := signJWT(t, key, baseClaims(now)) // acr AAL2, amr [pwd,mfa]

	// required acr not satisfied
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredACR: "AAL3"}); err == nil {
		t.Fatal("required acr AAL3 must fail for an AAL2 token")
	}
	// required acr satisfied
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredACR: "AAL2"}); err != nil {
		t.Fatalf("required acr AAL2 should pass: %v", err)
	}
	// required amr missing (phr not present)
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredAMR: []string{"phr"}}); err == nil {
		t.Fatal("required amr phr must fail when the token has only pwd,mfa")
	}
	// required amr present
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredAMR: []string{"mfa"}}); err != nil {
		t.Fatalf("required amr mfa should pass: %v", err)
	}
}

func TestValidateConfigurableAssuranceClaims(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()

	// Entra-style token: assurance carried under "acrs" as an ARRAY, and amr under a custom claim name.
	conn := sampleConn()
	conn.ACRClaim = "acrs"
	conn.AMRClaim = "authn_methods"
	claims := baseClaims(now)
	delete(claims, "acr")
	claims["acrs"] = []any{"c1", "c2"}
	claims["authn_methods"] = []any{"fido"}
	tok := signJWT(t, key, claims)

	// required acr satisfied by membership in the array claim; identity records the satisfied value.
	id, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredACR: "c1"})
	if err != nil {
		t.Fatalf("required acr c1 should be satisfied by acrs=[c1,c2]: %v", err)
	}
	if id.ACR != "c1" {
		t.Fatalf("identity acr should record the satisfied value c1, got %q", id.ACR)
	}
	// a value not in the array fails closed
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredACR: "c9"}); err == nil {
		t.Fatal("required acr c9 must fail when acrs has only c1,c2")
	}
	// amr under the custom claim is honored
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredAMR: []string{"fido"}}); err != nil {
		t.Fatalf("required amr fido under a custom amr_claim should pass: %v", err)
	}
	// with AMRClaim remapped, the standard "amr" (pwd,mfa) is NOT consulted
	if _, err := ValidateIDToken(conn, tok, ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, RequiredAMR: []string{"pwd"}}); err == nil {
		t.Fatal("with AMRClaim=authn_methods, the standard amr must not satisfy")
	}
}

func TestAuthorizeURLAndPKCE(t *testing.T) {
	conn := sampleConn()
	u := AuthorizeURL(conn, AuthorizeParams{RedirectURI: "https://edge/callback", State: "STATE", Nonce: "NONCE", CodeChallenge: "CHAL"})
	for _, want := range []string{"response_type=code", "client_id=client-1", "code_challenge=CHAL", "code_challenge_method=S256", "state=STATE", "nonce=NONCE", "scope=openid"} {
		if !strings.Contains(u, want) {
			t.Fatalf("authorize url missing %q: %s", want, u)
		}
	}
	// RFC 7636 known PKCE vector
	if got := CodeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("PKCE S256 challenge mismatch: %s", got)
	}
}

func flip(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
