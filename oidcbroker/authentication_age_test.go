package oidcbroker

import (
	"net/url"
	"testing"
	"time"
)

func TestValidateAuthenticationAge(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC().Truncate(time.Second)
	age := int64(300)
	for _, tc := range []struct {
		name  string
		value any
		pass  bool
	}{
		{"recent", now.Add(-time.Minute).Unix(), true},
		{"missing", nil, false}, {"old", now.Add(-7 * time.Minute).Unix(), false},
		{"future", now.Add(2 * time.Minute).Unix(), false}, {"string", "1", false},
		{"fractional", float64(now.Unix()) + 0.5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseClaims(now)
			if tc.value != nil {
				claims["auth_time"] = tc.value
			}
			id, err := ValidateIDToken(sampleConn(), signJWT(t, key, claims), ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, MaxAgeSeconds: &age})
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%v err=%v", tc.pass, err)
			}
			if tc.pass && id.AuthTime != now.Add(-time.Minute).Format(time.RFC3339) {
				t.Fatal("must preserve IdP authentication time, not token issue time")
			}
		})
	}
	zero := int64(0)
	u, _ := url.Parse(AuthorizeURL(sampleConn(), AuthorizeParams{MaxAgeSeconds: &zero}))
	if !u.Query().Has("max_age") || u.Query().Get("max_age") != "0" {
		t.Fatal("zero max_age must request active authentication")
	}
}
