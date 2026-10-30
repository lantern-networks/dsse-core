package oidcbroker

import (
	"testing"
	"time"
)

func TestSignedIDTokenMustPostdateAdministratorRevocation(t *testing.T) {
	key, jwks := testKeyAndJWKS(t)
	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.Add(-10*time.Second + 500*time.Millisecond)
	for _, test := range []struct {
		name string
		auth any
		want bool
	}{
		{"missing", nil, false}, {"old-sso", now.Add(-time.Hour).Unix(), false},
		{"same-second-as-revocation", now.Add(-10 * time.Second).Unix(), false},
		{"post-revocation", now.Add(-9 * time.Second).Unix(), true},
		{"future", now.Add(time.Second).Unix(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := baseClaims(now)
			claims["iat"] = now.Unix()
			if test.auth != nil {
				claims["auth_time"] = test.auth
			}
			_, err := ValidateIDToken(sampleConn(), signJWT(t, key, claims), ValidateOptions{JWKS: jwks, ExpectedNonce: "NONCE", Now: now, AuthenticationNotBefore: cutoff})
			if (err == nil) != test.want {
				t.Fatalf("accepted=%v want=%v: %v", err == nil, test.want, err)
			}
		})
	}
}

func TestAuthenticationAtExactRevocationInstantIsNotNew(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if e := ValidateAuthenticationAfter(now.Format(time.RFC3339), now, now.Add(time.Second)); e == nil {
		t.Fatal("authentication at the revocation instant was considered later")
	}
}
