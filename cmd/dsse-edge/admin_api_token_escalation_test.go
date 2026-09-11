package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// tokenMintHarness builds a server whose admin auth store holds two SESSIONS: a customer's own administrator
// and the operator. Sessions rather than bearer tokens because a token may not mint another token — which is
// why the live escalation went through a browser session, and why a test driven by the harness bearers would
// measure that unrelated refusal instead of this one.
func tokenMintHarness(t *testing.T) (http.Handler, *adminAuthStore) {
	t.Helper()
	now := time.Now().UTC()
	auth := newAdminAuthStore()
	for _, seat := range []struct {
		session, principal, tenant string
		roles                      []string
	}{
		{"sess_customer", "adm_customer", "tenant_northwind", []string{"admin"}},
		// ★ THE OPERATOR NEEDS "admin" IN ITS OWN ORGANIZATION TOO, and that is a provisioning fact worth
		// stating: super_admin holds neither admin.api_tokens.write nor any other tenant-side permission, so an
		// operator principal with super_admin ALONE cannot mint even its own machine credential. On the lab it
		// has exactly that, which is one reason everything ran as the break-glass token.
		{"sess_operator", "adm_operator", "tenant_operator_001", []string{"super_admin", "admin"}},
	} {
		auth.UpsertPrincipal(adminPrincipal{
			ID: seat.principal, TenantID: seat.tenant, Subject: seat.principal,
			Email: seat.principal + "@example.invalid", Roles: seat.roles, IDPID: "keycloak_lab",
			Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		})
		auth.UpsertSession(adminSession{
			ID: seat.session, TenantID: seat.tenant, AdminPrincipalID: seat.principal,
			Subject: seat.principal, Roles: seat.roles, MFAState: "satisfied",
			CreatedAt: now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
			Metadata: map[string]any{adminCSRFTokenKey: "csrf_" + seat.session},
		})
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth,
		TenantModelStore: newAdminTenantModelStore(model.PolicyBundle{}, now),
	})
	return handler, auth
}

// mintAdminAPIToken asks for an API token as one of those sessions.
func mintAdminAPIToken(t *testing.T, handler http.Handler, session string, roles []string, scopes ...string) (int, string) {
	if len(scopes) == 0 {
		scopes = []string{"admin.state.read"}
	}
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "probe", "roles": roles, "scopes": scopes})
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: session})
	req.Header.Set("x-csrf-token", "csrf_"+session)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// ★ A CUSTOMER'S OWN ADMINISTRATOR COULD MINT AN OWNER TOKEN (2026-08-16, measured on the reference lab
// before it was understood). POST /admin/api-tokens is gated on admin.api_tokens.write, which every tenant
// `admin` holds — correctly, since minting a token for your own organization is ordinary work. Nothing
// checked WHICH roles the token carried.
//
// Live, with northwind's real administrator (roles ["admin"], no cross-tenant permission): the mint returned
// 201, the token resolved with permissions ["*"], and with it that customer listed every organization in the
// deployment, read the deployment's interception PKI, and created an organization.
//
// The invite and role-change routes both guard the tenant-admin threshold; this route had no guard at all.
func TestATenantAdminCannotMintATokenAboveItself(t *testing.T) {
	handler, _ := tokenMintHarness(t)

	for _, role := range []string{"owner", "super_admin"} {
		code, response := mintAdminAPIToken(t, handler, "sess_customer", []string{role})
		if code != http.StatusForbidden {
			t.Fatalf("a tenant administrator minted a %q token: HTTP %d %s", role, code, response)
		}
		if !strings.Contains(response, "you do not hold yourself") {
			t.Fatalf("the refusal does not say why: %s", response)
		}
	}

	// The control, same caller: a token at or below its own level is ordinary work and must still succeed.
	// Without it, "the mint was refused" is also what a broken route looks like.
	for _, role := range []string{"admin", "analyst", "auditor"} {
		if code, response := mintAdminAPIToken(t, handler, "sess_customer", []string{role}); code != http.StatusCreated {
			t.Fatalf("a tenant administrator could not mint a %q token for its own organization: HTTP %d %s",
				role, code, response)
		}
	}
}

// And the operator can, because it holds those roles itself. The guard is about the gap between the minter
// and the minted, not about the role's name.
func TestAnOperatorCanStillMintTheOperatorRole(t *testing.T) {
	handler, _ := tokenMintHarness(t)

	if code, response := mintAdminAPIToken(t, handler, "sess_operator", []string{"super_admin"}); code != http.StatusCreated {
		t.Fatalf("the operator could not mint a named machine credential: HTTP %d %s", code, response)
	}
}

// ★ AND super_admin HAD TO BECOME A TOKEN ROLE AT ALL. It is a valid principal role and was not a valid token
// role, so the operator's automation had no least-privileged option: it ran as `owner` ("*", strictly more) or
// as the shared break-glass token ("*" AND anonymous). A list that omits the right answer pushes every caller
// to the most-privileged one.
func TestTheOperatorRoleIsAvailableToATokenAtAll(t *testing.T) {
	if !adminAPITokenRoles["super_admin"] {
		t.Fatal("super_admin is not a role a token may carry, so the operator cannot have a named credential")
	}
	if len(normalizedAdminRoles([]string{"super_admin"}, nil)) != 1 {
		t.Fatal("the normaliser still drops super_admin, so the role list and the normaliser disagree")
	}
}

// An unknown role is refused rather than dropped. Asking for ["admin","super_admin"] used to produce a token
// holding ["admin"] with a 201 — weaker than the one asked for, and nothing said so.
func TestAnUnknownRoleIsRefusedRatherThanQuietlyDropped(t *testing.T) {
	handler, _ := tokenMintHarness(t)

	code, response := mintAdminAPIToken(t, handler, "sess_operator", []string{"admin", "superuser"})
	if code == http.StatusCreated {
		t.Fatalf("a token was issued for a role this deployment does not have: %s", response)
	}
	if !strings.Contains(response, "no such role") || !strings.Contains(response, "superuser") {
		t.Fatalf("the refusal does not name the unknown role: %s", response)
	}
	// The control: the known half alone still works, so this is a refusal of the unknown role and not of the
	// request shape.
	if code, response := mintAdminAPIToken(t, handler, "sess_operator", []string{"admin"}); code != http.StatusCreated {
		t.Fatalf("the control failed: a known role was refused too: HTTP %d %s", code, response)
	}
}

// ★ AN EITHER-OF ROUTE WAS UNREACHABLE BY ANY API TOKEN (found live, 2026-08-16). The ROLE check learned the
// "a|b" syntax when a handful of routes became "a tenant act on your own organization, an operator act on
// somebody else's". The SCOPE check did not: it compared the token's scopes against the literal string
// "admin.enrollment.read|admin.tenant.admin", which no scope list contains. Those routes therefore answered
// 403 to every named token while answering 200 to a browser session and to the shared break-glass owner
// token — which is one more reason a deployment ends up running on the break-glass token.
func TestAnEitherOfRouteIsReachableByATokenHoldingEitherScope(t *testing.T) {
	for _, holds := range []string{"admin.enrollment.read", "admin.tenant.admin"} {
		identity := adminIdentity{AuthMethod: "admin_api_token", Scopes: []string{holds}}
		if !adminScopeAllowed(identity, "admin.enrollment.read|admin.tenant.admin") {
			t.Fatalf("a token scoped %q cannot reach a route that accepts it as one of two alternatives", holds)
		}
	}
	// The control: a token holding NEITHER is still refused, so this widened the reading of the gate and not
	// the gate itself.
	unrelated := adminIdentity{AuthMethod: "admin_api_token", Scopes: []string{"admin.logs.read"}}
	if adminScopeAllowed(unrelated, "admin.enrollment.read|admin.tenant.admin") {
		t.Fatal("a token holding neither alternative was allowed through")
	}
	// And a single-permission gate is unchanged.
	if !adminScopeAllowed(adminIdentity{AuthMethod: "admin_api_token", Scopes: []string{"admin.policy.write"}}, "admin.policy.write") {
		t.Fatal("an ordinary single-permission gate stopped working")
	}
}
