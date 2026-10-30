package oidcbroker

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProviderAuthorizationRequirements(t *testing.T) {
	conn := sampleConn()
	conn.Type = "entra"
	p := AuthorizeParams{ACRValues: "c3", RequiredAMR: []string{"mfa"}}
	if err := ValidateAuthorizeParams(conn, p); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(AuthorizeURL(conn, p))
	if u.Query().Has("acr_values") {
		t.Fatal("Entra context must use claims, not acr_values")
	}
	var claims struct {
		ID map[string]struct {
			Essential bool   `json:"essential"`
			Value     string `json:"value"`
		} `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(u.Query().Get("claims")), &claims); err != nil {
		t.Fatal(err)
	}
	if !claims.ID["acrs"].Essential || claims.ID["acrs"].Value != "c3" || !claims.ID["amr"].Essential {
		t.Fatal("missing signed claim request")
	}
	for _, bad := range []string{"phishing_resistant", "c0", "c100", "c03", "c1 c2"} {
		if ValidateAuthorizeParams(conn, AuthorizeParams{ACRValues: bad}) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	conn.Type = "google"
	zero := int64(0)
	if ValidateAuthorizeParams(conn, AuthorizeParams{MaxAgeSeconds: &zero}) == nil {
		t.Fatal("Google reauth must not silently become ordinary login")
	}
	if err := ValidateAuthorizeParams(conn, AuthorizeParams{}); err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(AuthorizeURL(conn, AuthorizeParams{}))
	if u.Query().Has("claims") {
		t.Fatal("ordinary login unexpectedly requests extra claims")
	}
	age := int64(300)
	if err := ValidateAuthorizeParams(conn, AuthorizeParams{MaxAgeSeconds: &age}); err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse(AuthorizeURL(conn, AuthorizeParams{MaxAgeSeconds: &age}))
	if u.Query().Has("max_age") || !strings.Contains(u.Query().Get("claims"), "auth_time") {
		t.Fatal("Google age validation confused with forcing reauthentication")
	}
	conn.Type = "okta"
	u, _ = url.Parse(AuthorizeURL(conn, AuthorizeParams{ACRValues: "urn:okta:loa:2fa:any", MaxAgeSeconds: &zero}))
	if u.Query().Get("acr_values") != "urn:okta:loa:2fa:any" || u.Query().Get("max_age") != "0" {
		t.Fatal("Okta request lost")
	}
}

func TestFreshAuthenticationUsesAttemptStart(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-45 * time.Second)
	zero := int64(0)
	for _, tc := range []struct {
		name    string
		at      time.Time
		started time.Time
		pass    bool
	}{
		{"during prompt", start.Add(5 * time.Second), start, true},
		{"at start", start, start, true},
		{"old SSO", start.Add(-time.Second), start, false},
		{"future", now.Add(time.Second), start, false},
		{"missing attempt", start, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseClaims(now)
			claims["auth_time"] = tc.at.Unix()
			_, err := ValidateIDToken(sampleConn(), signJWT(t, key, claims), ValidateOptions{JWKS: jwks, Now: now, ExpectedNonce: "NONCE", MaxAgeSeconds: &zero, AuthenticationStartedAt: tc.started})
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%v err=%v", tc.pass, err)
			}
		})
	}
}

func TestEntraValidatesRequestedContextAndSubject(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC()
	conn := sampleConn()
	conn.Type = "entra"
	claims := baseClaims(now)
	claims["acrs"] = []string{"c1", "c3"}
	id, err := ValidateIDToken(conn, signJWT(t, key, claims), ValidateOptions{JWKS: jwks, Now: now, RequiredACR: "c3"})
	if err != nil || id.ACR != "c3" {
		t.Fatalf("context verification failed: %v", err)
	}
	delete(claims, "sub")
	if _, err = ValidateIDToken(conn, signJWT(t, key, claims), ValidateOptions{JWKS: jwks, Now: now}); err == nil {
		t.Fatal("missing stable subject accepted")
	}
}
