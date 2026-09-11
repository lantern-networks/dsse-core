package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

// enroll_eligibility_idp.go — proving a device may enrol with an IdP login instead of a shared secret.
//
// WHAT IT REPLACES. Enrolment eligibility is a single SHARED, NON-EXPIRING token today; the file that
// implements it says outright that the model must not ship to production. Everything wrong with it follows
// from being one secret: it has to be present on every machine that will ever enrol, it does not expire, it
// names nobody, and anyone who obtains it can enrol an arbitrary device into the fleet. Rotating it means
// touching every pending endpoint at once.
//
// An IdP login fixes each of those. The token is per-person and short-lived, the IdP can revoke it, and the
// enrolment carries WHO performed it — which is the fact an operator wants months later when a device turns
// out to be somewhere it should not be. It also needs no new infrastructure: the constraint on this product is
// no AD CS to build and no mandatory MDM, and an IdP is already required for everything else.
//
// WHAT IT DOES NOT CLAIM. This proves a PERSON is entitled to enrol a device. It does not prove anything about
// the DEVICE — that it is corporate-owned, that its key is in hardware, that it is not a laptop in a café. That
// is a separate signal (TPM / Secure Enclave attestation, MDM enrolment proof) and is deliberately not
// conflated here: an operator reading "enrolled by alice@example.com" must not take it to mean the machine was
// verified. The device half is tracked separately.
//
// FAIL CLOSED. Every validation failure refuses enrolment. A token that cannot be checked is not a token that
// passes — this endpoint is unauthenticated and public by nature, so ambiguity has to resolve to "no".

// idpEnrollmentEligibility validates an ID token presented as enrolment eligibility and returns the identity
// it asserts, plus a short non-secret description for the audit trail.
type idpEnrollmentEligibility struct {
	// Connections resolves the IdP connection to validate against. A single configured connection keeps the
	// device from CHOOSING its issuer — otherwise anyone could stand up an IdP and enrol.
	Connections func() (idpregistry.Connection, bool)
	// FetchJWKS retrieves the connection's signing keys.
	FetchJWKS func(idpregistry.Connection) (oidcbroker.JWKS, error)
	// RequiredGroup, when set, additionally demands the token's groups claim contain it — so "any employee"
	// can be narrowed to "someone who is allowed to enrol devices".
	RequiredGroup string
	// TenantID scopes the registry lookup. Set at registration time, where the tenant is known; the connection
	// itself is still resolved per request.
	TenantID string
	Now      func() time.Time
}

// verify checks the presented token and returns the enrolling identity.
func (e idpEnrollmentEligibility) verify(rawToken string) (oidcbroker.Identity, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return oidcbroker.Identity{}, fmt.Errorf("no IdP token presented")
	}
	if e.Connections == nil || e.FetchJWKS == nil {
		return oidcbroker.Identity{}, fmt.Errorf("IdP-backed enrolment is not configured")
	}
	conn, ok := e.Connections()
	if !ok {
		return oidcbroker.Identity{}, fmt.Errorf("no IdP connection is configured for enrolment")
	}
	jwks, err := e.FetchJWKS(conn)
	if err != nil {
		// Reachability failure REFUSES rather than allowing. An IdP that cannot be reached is exactly when an
		// attacker would like enrolment to fall back to something weaker.
		return oidcbroker.Identity{}, fmt.Errorf("could not fetch the IdP's signing keys: %w", err)
	}
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now()
	}
	identity, err := oidcbroker.ValidateIDToken(conn, rawToken, oidcbroker.ValidateOptions{JWKS: jwks, Now: now})
	if err != nil {
		return oidcbroker.Identity{}, fmt.Errorf("IdP token rejected: %w", err)
	}
	if group := strings.TrimSpace(e.RequiredGroup); group != "" {
		found := false
		for _, g := range identity.Groups {
			if strings.EqualFold(strings.TrimSpace(g), group) {
				found = true
				break
			}
		}
		if !found {
			// Named without echoing the token's whole group list: the refusal has to be actionable without
			// turning the log into a directory dump.
			return oidcbroker.Identity{}, fmt.Errorf("the signed-in user is not in the group permitted to enrol devices (%q)", group)
		}
	}
	return identity, nil
}

// enrolmentAttribution renders the non-secret description recorded against the device.
//
// Deliberately NOT the token, and not anything that could be replayed: a subject and an email, which is what
// answers "who put this device in the fleet" months later.
func enrolmentAttribution(identity oidcbroker.Identity) string {
	who := strings.TrimSpace(identity.Email)
	if who == "" {
		who = strings.TrimSpace(identity.Username)
	}
	if who == "" {
		who = strings.TrimSpace(identity.Subject)
	}
	if who == "" {
		who = "unknown"
	}
	return fmt.Sprintf("enrolled via IdP login by %s (issuer %s)", who, strings.TrimSpace(identity.Issuer))
}

// fetchEnrollmentJWKS retrieves a connection's JWKS over plain HTTP(S). Separated so tests can substitute it
// and so the timeout is stated once.
func fetchEnrollmentJWKS(conn idpregistry.Connection) (oidcbroker.JWKS, error) {
	uri := strings.TrimSpace(conn.JWKSURI)
	if uri == "" {
		return oidcbroker.JWKS{}, fmt.Errorf("connection has no jwks_uri")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(uri)
	if err != nil {
		return oidcbroker.JWKS{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcbroker.JWKS{}, fmt.Errorf("jwks_uri returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return oidcbroker.JWKS{}, err
	}
	var parsed oidcbroker.JWKS
	if err := json.Unmarshal(body, &parsed); err != nil {
		return oidcbroker.ParseJWKS(body)
	}
	return parsed, nil
}

// buildEnrollIdPEligibility assembles the checker, or returns nil when no connection is configured (in which
// case only the shared token is accepted and nothing changes for an existing deployment).
//
// The registry is reached through a getter rather than captured directly because the enrolment endpoint is
// registered BEFORE the registry is created — its persister needs configuration that is assembled later. The
// closure only runs per request, long after startup, so a nil check covers the window; expressing it as an
// ordering constraint instead would be a rule nobody remembers when moving code.
func buildEnrollIdPEligibility(connectionID, requiredGroup string, registry func() *idpregistry.Store) *idpEnrollmentEligibility {
	connectionID = strings.TrimSpace(connectionID)
	if connectionID == "" || registry == nil {
		return nil
	}
	el := &idpEnrollmentEligibility{
		FetchJWKS:     fetchEnrollmentJWKS,
		RequiredGroup: strings.TrimSpace(requiredGroup),
	}
	el.Connections = func() (idpregistry.Connection, bool) {
		store := registry()
		if store == nil {
			return idpregistry.Connection{}, false
		}
		// Resolved per request, so adding, repointing or REMOVING the connection in the Console takes effect
		// immediately — a connection that is taken away stops being accepted now, not at the next restart.
		return store.Get(el.TenantID, connectionID)
	}
	return el
}

// theIdPRegistry is this node's registry of which identity provider may sign a user in, for each
// organization. It is read by the enrolment eligibility checker and by the control plane's config-bundle
// publisher — two things that both run per REQUEST, long after the registry is built.
//
// The checker is wired while the Edge's configuration is assembled; the registry is created later, because its
// persister needs that same configuration. Passing it through would mean either reordering startup around one
// endpoint's convenience or threading a parameter through several layers that have no other use for it.
//
// The closure only runs per REQUEST — long after startup — so the window is closed by a nil check rather than
// by an ordering rule nobody would remember when moving code. Stored atomically because it is written once
// during startup and read by request goroutines afterwards.
var theIdPRegistry atomic.Pointer[idpregistry.Store]
