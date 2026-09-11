package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
	oidcbroker "github.com/lantern-networks/dsse-core/oidcbroker"
)

// idpConnectionCheck is one named probe in a connection test (e.g. "jwks", "discovery").
type idpConnectionCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// idpConnectionTestResult is the "Test" verdict the Console shows as OK / not-OK after registering an IdP. It
// validates the connection WITHOUT a user login: the IdP's published signing keys must be fetchable + parseable
// (so the broker can validate tokens), and — best effort — its OIDC discovery document must agree on the issuer
// (a mismatch means every login would fail the broker's iss check). Discovery being unreachable is advisory
// (some deployments configure explicit endpoints without standard discovery) and does not fail the test.
type idpConnectionTestResult struct {
	OK     bool                 `json:"ok"`
	Checks []idpConnectionCheck `json:"checks"`
}

// testIdPConnection runs the non-interactive connection probes and returns the verdict.
func testIdPConnection(conn idpregistry.Connection) idpConnectionTestResult {
	// ★★★ TEST IT THE WAY THE SIGN-IN REACHES IT (2026-09-03, measured minutes after the same mistake was
	// fixed in the application reachability test). This built its own http.Client, so it verified against the
	// container's system roots while the broker verifies against the authority the connection NAMES — and the
	// screen said "Not reachable: certificate signed by unknown authority" about a provider the deployment
	// could reach perfectly well. A check that answers a different question from the flow is worse than none:
	// it sends an operator to fix something that is not broken.
	client, cerr := idpHTTPClient(&http.Client{Timeout: 8 * time.Second}, conn)
	if cerr != nil {
		return idpConnectionTestResult{OK: false, Checks: []idpConnectionCheck{{
			Name: "certificate authority", OK: false, Detail: cerr.Error(),
		}}}
	}

	// 1) JWKS: reachable + parseable + at least one RSA signing key. This is the hard requirement — without it
	//    the broker cannot verify any ID token.
	jwks := idpConnectionCheck{Name: "jwks"}
	switch {
	case strings.TrimSpace(conn.JWKSURI) == "":
		jwks.Detail = "no jwks_uri configured"
	default:
		if n, err := fetchJWKSRSAKeyCount(client, conn.JWKSURI); err != nil {
			jwks.Detail = err.Error()
		} else if n == 0 {
			jwks.Detail = "jwks document has no RSA signing keys"
		} else {
			jwks.OK = true
			jwks.Detail = fmt.Sprintf("reachable, %d RSA key(s)", n)
		}
	}

	// 2) OIDC discovery: the IdP's <issuer>/.well-known/openid-configuration must echo the same issuer (the
	//    broker enforces iss == conn.Issuer, so a mismatch breaks every login). Unreachable discovery is
	//    advisory; a reachable-but-mismatched issuer is a hard failure.
	disc := idpConnectionCheck{Name: "discovery"}
	discoveryHardFail := false
	if meta, err := fetchOIDCDiscovery(client, conn.Issuer); err != nil {
		disc.Detail = "advisory: discovery not reachable (" + err.Error() + ")"
	} else if !sameIssuer(meta.Issuer, conn.Issuer) {
		disc.Detail = fmt.Sprintf("issuer mismatch: discovery=%q vs configured=%q", meta.Issuer, conn.Issuer)
		discoveryHardFail = true
	} else {
		disc.OK = true
		disc.Detail = "issuer matches" + endpointAgreement(meta, conn)
	}

	return idpConnectionTestResult{
		OK:     jwks.OK && !discoveryHardFail,
		Checks: []idpConnectionCheck{jwks, disc},
	}
}

func fetchJWKSRSAKeyCount(client *http.Client, jwksURI string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("jwks_uri returned %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	set, err := oidcbroker.ParseJWKS(data)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range set.Keys {
		if strings.EqualFold(k.Kty, "RSA") {
			n++
		}
	}
	return n, nil
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func fetchOIDCDiscovery(client *http.Client, issuer string) (oidcDiscovery, error) {
	base := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if base == "" {
		return oidcDiscovery{}, fmt.Errorf("no issuer configured")
	}
	req, err := http.NewRequest(http.MethodGet, base+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("returned %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var meta oidcDiscovery
	if err := json.Unmarshal(data, &meta); err != nil {
		return oidcDiscovery{}, fmt.Errorf("parse discovery: %w", err)
	}
	return meta, nil
}

func sameIssuer(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

// endpointAgreement appends a short note when the configured endpoints disagree with discovery (advisory — the
// broker uses the configured endpoints, but a mismatch is usually a copy-paste error worth surfacing).
func endpointAgreement(meta oidcDiscovery, conn idpregistry.Connection) string {
	var diffs []string
	if e := strings.TrimSpace(conn.AuthorizationEndpoint); e != "" && meta.AuthorizationEndpoint != "" && e != meta.AuthorizationEndpoint {
		diffs = append(diffs, "authorization_endpoint")
	}
	if e := strings.TrimSpace(conn.TokenEndpoint); e != "" && meta.TokenEndpoint != "" && e != meta.TokenEndpoint {
		diffs = append(diffs, "token_endpoint")
	}
	if e := strings.TrimSpace(conn.JWKSURI); e != "" && meta.JWKSURI != "" && e != meta.JWKSURI {
		diffs = append(diffs, "jwks_uri")
	}
	if len(diffs) == 0 {
		return ", endpoints agree"
	}
	return ", but these differ from discovery: " + strings.Join(diffs, ", ")
}
