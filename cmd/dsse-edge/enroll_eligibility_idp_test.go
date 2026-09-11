package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

// Enrolment eligibility proved by an IdP login instead of one shared, non-expiring secret.
//
// What matters here is the refusals. The endpoint is unauthenticated and public by nature, so every case that
// cannot be positively verified has to resolve to "no" — a forged token, an expired one, an IdP that cannot be
// reached, a user outside the group permitted to enrol.

func idpTestKey(t *testing.T) (*rsa.PrivateKey, oidcbroker.JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	raw := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"test","alg":"RS256","use":"sig","n":%q,"e":%q}]}`, n, e)
	jwks, err := oidcbroker.ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key, jwks
}

func idpTestToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 5 /* crypto.SHA256 */, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func idpTestEligibility(t *testing.T, jwks oidcbroker.JWKS, requiredGroup string, reachable bool) idpEnrollmentEligibility {
	t.Helper()
	conn := idpregistry.Connection{
		IdPID: "lab", Type: "oidc", Issuer: "https://idp.example.com", ClientID: "dsse-edge",
		VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain", GroupsClaim: "groups",
	}
	return idpEnrollmentEligibility{
		Connections: func() (idpregistry.Connection, bool) { return conn, true },
		FetchJWKS: func(idpregistry.Connection) (oidcbroker.JWKS, error) {
			if !reachable {
				return oidcbroker.JWKS{}, fmt.Errorf("connection refused")
			}
			return jwks, nil
		},
		RequiredGroup: requiredGroup,
		Now:           func() time.Time { return time.Unix(1800000000, 0).UTC() },
	}
}

func idpTestClaims(extra map[string]any) map[string]any {
	claims := map[string]any{
		"iss": "https://idp.example.com", "aud": "dsse-edge",
		"sub": "user-1", "email": "alice@example.com", "email_verified": true,
		"exp": 1800003600, "iat": 1799999900,
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

func TestIdPEnrolmentAcceptsAValidLogin(t *testing.T) {
	key, jwks := idpTestKey(t)
	el := idpTestEligibility(t, jwks, "", true)

	identity, err := el.verify(idpTestToken(t, key, idpTestClaims(nil)))
	if err != nil {
		t.Fatalf("a valid IdP login was refused: %v", err)
	}
	if identity.Email != "alice@example.com" {
		t.Fatalf("identity = %+v", identity)
	}

	// The attribution is what a shared token can never give: who put this device in the fleet.
	note := enrolmentAttribution(identity)
	if !strings.Contains(note, "alice@example.com") {
		t.Fatalf("attribution %q does not name the enrolling user", note)
	}
	if strings.Contains(note, ".") && strings.Count(note, ".") > 6 {
		t.Fatalf("attribution looks like it contains a token: %q", note)
	}
}

// The refusals. Each is a way an unauthenticated public endpoint gets abused.
func TestIdPEnrolmentRefusals(t *testing.T) {
	key, jwks := idpTestKey(t)
	otherKey, _ := idpTestKey(t)

	cases := []struct {
		name  string
		build func() (idpEnrollmentEligibility, string)
		want  string
	}{
		{"no token at all", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", true), ""
		}, "no IdP token"},
		{"signed by somebody else's key", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", true), idpTestToken(t, otherKey, idpTestClaims(nil))
		}, "rejected"},
		{"expired", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", true), idpTestToken(t, key, idpTestClaims(map[string]any{"exp": 1799000000}))
		}, "rejected"},
		{"issued by a different IdP", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", true), idpTestToken(t, key, idpTestClaims(map[string]any{"iss": "https://evil.example.net"}))
		}, "rejected"},
		{"meant for a different audience", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", true), idpTestToken(t, key, idpTestClaims(map[string]any{"aud": "some-other-app"}))
		}, "rejected"},
		// An IdP that cannot be reached must REFUSE, not fall back to something weaker — unreachability is
		// exactly the state an attacker would like enrolment to degrade in.
		{"IdP unreachable", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "", false), idpTestToken(t, key, idpTestClaims(nil))
		}, "signing keys"},
		{"user outside the group permitted to enrol", func() (idpEnrollmentEligibility, string) {
			return idpTestEligibility(t, jwks, "device-enrollers", true),
				idpTestToken(t, key, idpTestClaims(map[string]any{"groups": []any{"everyone"}}))
		}, "not in the group"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el, token := tc.build()
			if _, err := el.verify(token); err == nil {
				t.Fatalf("%s was ACCEPTED — this endpoint is public, so anything unverifiable must refuse", tc.name)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused, but the reason %q does not mention %q — an operator cannot act on it", err, tc.want)
			}
		})
	}
}

// Group membership narrows "any employee" to "someone allowed to enrol devices".
func TestIdPEnrolmentAcceptsAMemberOfTheRequiredGroup(t *testing.T) {
	key, jwks := idpTestKey(t)
	el := idpTestEligibility(t, jwks, "device-enrollers", true)
	token := idpTestToken(t, key, idpTestClaims(map[string]any{"groups": []any{"everyone", "device-enrollers"}}))
	if _, err := el.verify(token); err != nil {
		t.Fatalf("a member of the permitted group was refused: %v", err)
	}
}
