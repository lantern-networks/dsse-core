package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Centralized admin auth (docs/admin_auth_centralization_design.md, slice 1).
//
// The control plane is the admin identity/session authority; the enforcement Edge is a relying party. When
// the Edge sees an admin_session cookie it does not know locally, it INTROSPECTS the session against the
// control plane's GET /admin/session (forwarding the cookie) and, on 200, builds the admin identity from the
// authoritative response (principal / roles / scopes / csrf). Fail-closed: any error or non-200 = not
// authenticated (the caller continues to other auth methods / denies).

// sessionIntrospector validates admin_session cookies against the control plane's session endpoint.
type sessionIntrospector struct {
	url    string
	client *http.Client
}

// adminSessionAuthority is the process-wide introspector, set in main when -admin-session-authority-url is
// configured. nil = no remote authority (the Edge is the sole session authority, legacy behavior).
var adminSessionAuthority *sessionIntrospector

// newSessionIntrospector builds an introspector. caFile, when set, is the ONLY trust anchor for the
// authority's TLS (the reference edge.crt, whose SANs cover controlplane); empty = system roots.
func newSessionIntrospector(url, caFile string) (*sessionIntrospector, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caFile) != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("admin-session-authority-ca %q contained no usable certificates", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &sessionIntrospector{
		url:    strings.TrimSpace(url),
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// currentURL is where this Edge asks the authority WHO a caller is, right now.
//
// ★★★ A FIXED URL MEANT ADMINISTRATION DIED WHEN LEADERSHIP MOVED (2026-08-25, reported from win-dev-1 and
// then reproduced). This is configured as the region's own internal control-plane door, which routes to
// whichever LOCAL control plane is the leader. When leadership is in ANOTHER region that door has no healthy
// backend, so every admin request landing on this Edge failed:
//
//	500 {"error":"admin authentication store is unavailable"}
//
// The control plane had not restarted and the token was perfectly good. The deployment simply had no way,
// from here, to ask who was calling. Minutes later the same token answered 200 — because leadership had come
// back — which is the worst kind of intermittent: it looks like a flaky credential.
//
// The config channel already learned this today and follows leadership through a per-region list. Identity
// has to follow it too, or a failover locks the operator out of the half of the deployment that is still
// running perfectly well.
//
// ★ THE CONFIGURED URL REMAINS THE FALLBACK. A single-region deployment has no list, and its one door is the
// right answer; the selector only overrides when it currently knows somewhere better.
func (s *sessionIntrospector) currentURL() string {
	if s == nil {
		return ""
	}
	if base := controlChannelCurrentBaseURL(); base != "" {
		if u, err := neturl.Parse(s.url); err == nil {
			if b, berr := neturl.Parse(base); berr == nil && b.Host != "" {
				u.Scheme, u.Host = b.Scheme, b.Host
				return u.String()
			}
		}
	}
	return s.url
}

// sessionIntrospectionResponse mirrors the fields GET /admin/session returns for a session-authed request.
type sessionIntrospectionResponse struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	// PrincipalLabel is WHO that id belongs to, in a form a person reads — an email, today.
	//
	// It travels with the introspection because an enforcing Edge has no other way to learn it: admin accounts
	// live on the authority by design, and the front door routes the account listing there too. Without it, a
	// record of who approved a device can only hold an id, and an id resolves to nobody once the account is
	// deleted — which is the ordinary end of the story for approvals, not an edge case.
	//
	// Empty when the authority cannot resolve it. Empty is honest; a guessed name would be worse than the id.
	PrincipalLabel string   `json:"principal_label,omitempty"`
	Roles          []string `json:"roles"`
	Scopes         []string `json:"scopes"`
	AuthMethod     string   `json:"auth_method"`
	CSRFToken      string   `json:"csrf_token"`
}

// introspect validates the cookie against the authority. Returns (identity, true) only for a 200 response
// describing an admin session. Errors are logged and reported as not-authenticated (fail-closed).
func (s *sessionIntrospector) introspect(ctx context.Context, cookieValue string) (adminIdentity, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.currentURL(), nil)
	if err != nil {
		return adminIdentity{}, false
	}
	req.Header.Set("Cookie", "admin_session="+cookieValue)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("admin session introspection: authority unreachable: %v", err)
		return adminIdentity{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return adminIdentity{}, false
	}
	var parsed sessionIntrospectionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return adminIdentity{}, false
	}
	// The authority must describe a real session (not a bearer/api-token resolution echoed back).
	if parsed.AuthMethod != "admin_session" || strings.TrimSpace(parsed.PrincipalID) == "" {
		return adminIdentity{}, false
	}
	return adminIdentity{
		PrincipalID:    parsed.PrincipalID,
		PrincipalLabel: strings.TrimSpace(parsed.PrincipalLabel),
		TenantID:       parsed.TenantID,
		Roles:          parsed.Roles,
		Scopes:         parsed.Scopes,
		AuthMethod:     "admin_session",
		CSRFToken:      parsed.CSRFToken,
	}, true
}

// introspectAPIToken resolves an ADMIN API TOKEN against the same authority.
//
// ★★★ WHY THIS HAD TO EXIST (2026-08-23, measured). Taking the admin-auth database off the enforcement Edges
// left them able to resolve a session cookie the control plane minted — and nothing else. An API token lives
// in the same store, so every automation that authenticates with a bearer started getting 401 from an Edge:
// the lab's own posture check lost six of its readings in one run, including "which devices are reporting",
// and the failures read as missing data rather than as refused authentication.
//
// The authority answers for both — GET /admin/session with a bearer returns that token's identity — so the
// relying-party path covers both. Kept as a separate method rather than loosening introspect(), because the
// cookie path must go on refusing an api-token answer: a cookie that resolves to something that is not a
// session is not a session.
// authorityUnreachable records that the LAST attempt to ask the authority who a caller is could not reach it
// at all. Read by the admin middleware so an unreachable authority answers "I could not ask" rather than
// "you are not who you say you are". Cleared by the next successful introspection.
var authorityUnreachable atomic.Bool

// AuthorityWasUnreachable reports and CLEARS the flag. Reading it clears it so the state cannot outlive the
// request that observed it — a sticky "unreachable" would turn one blip into a permanent 503.
func AuthorityWasUnreachable() bool { return authorityUnreachable.Swap(false) }

func (s *sessionIntrospector) introspectAPIToken(ctx context.Context, authorization string) (adminIdentity, bool) {
	authorization = strings.TrimSpace(authorization)
	if s == nil || authorization == "" {
		return adminIdentity{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.currentURL(), nil)
	if err != nil {
		return adminIdentity{}, false
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		// ★★★ UNREACHABLE IS NOT "WRONG CREDENTIAL" (2026-08-25, measured across a leadership move). This
		// answered false, which the middleware renders as 401 — so for the thirty seconds it takes the
		// control channel to notice that leadership left the region, a perfectly good operator token reads
		// as rejected. That is the shape win-dev-1 reported as "the token dies and comes back": an
		// intermittent 401 is indistinguishable from a credential problem, and it sends somebody to look at
		// the wrong thing at the worst moment.
		log.Printf("admin api-token introspection: authority unreachable: %v", err)
		authorityUnreachable.Store(true)
		return adminIdentity{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return adminIdentity{}, false
	}
	var parsed sessionIntrospectionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return adminIdentity{}, false
	}
	// The mirror of the rule above: this path presented a bearer, so the authority must describe a credential
	// of that kind. An answer that is a SESSION here would mean the authority resolved something other than
	// what was sent, and accepting it would let one credential's answer stand in for another's.
	if strings.TrimSpace(parsed.PrincipalID) == "" || parsed.AuthMethod == "admin_session" {
		return adminIdentity{}, false
	}
	return adminIdentity{
		PrincipalID:    parsed.PrincipalID,
		PrincipalLabel: strings.TrimSpace(parsed.PrincipalLabel),
		TenantID:       parsed.TenantID,
		Roles:          parsed.Roles,
		Scopes:         parsed.Scopes,
		AuthMethod:     parsed.AuthMethod,
	}, true
}

// adminPrincipalLabel resolves a principal id to something a person reads, from the account store this node
// holds. Empty when it cannot — a deployment whose accounts live elsewhere, or an account since deleted.
//
// Empty is deliberate rather than a fallback to the id: the caller already has the id, and a label that is
// sometimes an id and sometimes a name is a field nothing can render honestly.
func adminPrincipalLabel(store *localAdminCredentialStore, tenantID, principalID string) string {
	if store == nil || strings.TrimSpace(principalID) == "" {
		return ""
	}
	for _, account := range store.List(strings.TrimSpace(tenantID)) {
		if strings.EqualFold(strings.TrimSpace(account.PrincipalID), strings.TrimSpace(principalID)) {
			return strings.TrimSpace(account.Email)
		}
	}
	return ""
}
