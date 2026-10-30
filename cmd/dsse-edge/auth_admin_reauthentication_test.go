package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestAdminRevocationRequiresRealFreshAuthenticationAcrossPortalAndCP(t *testing.T) {
	for _, mode := range []string{"old-sso", "missing-auth-time", "fresh-reusable", "revoke-during-idp", "revoke-at-authority-mint"} {
		t.Run(mode, func(t *testing.T) {
			key, jwks := brokerTestKeyJWKS(t)
			now := time.Now().UTC().Truncate(time.Second)
			var issuer, nonce string
			var tokenAuth atomic.Int64
			tokenAuth.Store(now.Add(-time.Hour).Unix())
			if mode == "fresh-reusable" || mode == "revoke-at-authority-mint" {
				tokenAuth.Store(now.Add(-time.Second).Unix())
			}
			idpMux := http.NewServeMux()
			idpMux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
				nonce = r.URL.Query().Get("nonce")
				http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=fixture-code&state="+url.QueryEscape(r.URL.Query().Get("state")), 302)
			})
			idpMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				claims := map[string]any{"iss": issuer, "aud": "client", "sub": "user", "nonce": nonce, "email": "user@example.com", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
				if mode != "missing-auth-time" {
					claims["auth_time"] = tokenAuth.Load()
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, claims)})
			})
			idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(jwks) })
			idp := httptest.NewServer(idpMux)
			defer idp.Close()
			issuer = idp.URL
			registry := idpregistry.NewStore()
			if _, e := registry.Upsert(idpregistry.Connection{TenantID: "tenant", IdPID: "corp", Type: "oidc", Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks", ClientID: "client", DomainMode: "email_domain", VerifiedDomains: []string{"example.com"}}); e != nil {
				t.Fatal(e)
			}
			authTestAssign(t, registry, "tenant", "device", "user", "corp")
			authority := grantstore.NewStore()
			backend := &authLocalAuthority{}
			if e := authority.SetPersister(backend); e != nil {
				t.Fatal(e)
			}
			signer := newDeviceBindingSignerFromSecret("shared-test-deployment")
			gate := &federatedAuthGate{registry: registry, grants: authority, signer: signer, brokerBaseURL: "https://portal.example", tenantID: "tenant"}
			old := authTestBindGrant(t, gate, grantstore.Grant{GrantID: "old", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app.example:22", AuthTime: now.Add(-time.Hour).Format(time.RFC3339)})
			if _, e := authority.Mint(old, time.Hour, now.Add(-time.Minute)); e != nil {
				t.Fatal(e)
			}
			revoke := func(at time.Time) {
				t.Helper()
				if _, _, e := authority.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", at); e != nil {
					t.Fatal(e)
				}
			}
			if mode != "revoke-during-idp" {
				revoke(now.Add(-10 * time.Second))
			}
			cpMux := http.NewServeMux()
			registerAuthenticationGrantAuthority(cpMux, authority, "", func(*http.Request, string) bool { return true })
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "revoke-at-authority-mint" && r.URL.Path == "/authentication-grants/mint" {
					other := old
					other.GrantID = "race"
					other.AuthTime = now.Add(-time.Second).Format(time.RFC3339)
					if _, e := authority.Mint(other, time.Hour, now); e != nil {
						t.Fatal(e)
					}
					if _, _, e := authority.RequireReauthenticationForTenantContext(context.Background(), "tenant", "race", time.Now()); e != nil {
						t.Fatal(e)
					}
				}
				cpMux.ServeHTTP(w, r)
			}))
			defer cp.Close()
			var redundantReports atomic.Int32
			makePortal := func() *clientlessBroker {
				b := newClientlessBroker(registry, grantstore.NewStore(), idp.Client(), "https://portal.example", "tenant", time.Hour, signer)
				b.recoverySharedKey = true
				b.authority = &grantCPReporter{url: cp.URL + "/grant-report", client: cp.Client()}
				b.publishGrants = func(context.Context) { redundantReports.Add(1) }
				return b
			}
			first, second := makePortal(), makePortal()
			link := authTestSignedLink(gate, gate.stepUpURLWithRequirements("app.example:22", "device", "tenant", federatedRequirements{IdP: "corp", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}))
			start := httptest.NewRecorder()
			first.startForTest(start, httptest.NewRequest("GET", link, nil))
			if start.Code != 302 {
				t.Fatalf("start %d: %s", start.Code, start.Body)
			}
			location, _ := url.Parse(start.Header().Get("Location"))
			age := location.Query().Get("max_age")
			if mode != "revoke-during-idp" {
				if n, e := strconv.Atoi(age); e != nil || n < 0 || n > 11 {
					t.Fatalf("IdP freshness not requested: %q", age)
				}
			} else if age != "" {
				t.Fatal("natural login forced without revocation")
			}
			noRedirect := *idp.Client()
			noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			response, e := noRedirect.Get(location.String())
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
			if mode == "revoke-during-idp" {
				revoke(now.Add(-5 * time.Second))
			}
			request := httptest.NewRequest("GET", response.Header.Get("Location"), nil)
			for _, c := range start.Result().Cookies() {
				if c.Name == authSessionCookie {
					request.AddCookie(c)
				}
			}
			result := httptest.NewRecorder()
			second.handleCallback(result, request)
			if redundantReports.Load() != 0 {
				t.Fatal("authority-owned grant was synchronously reported again")
			}
			if mode == "fresh-reusable" {
				if result.Code != 200 {
					t.Fatalf("fresh callback %d: %s", result.Code, result.Body)
				}
				rows := authority.List("tenant")
				var fresh grantstore.Grant
				for _, g := range rows {
					if g.GrantID != "old" {
						fresh = g
					}
				}
				if fresh.GrantID == "" || fresh.AuthenticationRequestID != "" || fresh.ReauthenticationStartedAt != "" {
					t.Fatal("administrator reauthentication became a one-use grant")
				}
				for i := 0; i < 2; i++ {
					if !second.grants.Valid(fresh.GrantID, time.Now()) {
						t.Fatal("fresh grant not reusable")
					}
				}
			} else {
				if result.Code == 200 {
					t.Fatal("old SSO or concurrent revocation admitted")
				}
				if len(second.grants.List("tenant")) != 0 {
					t.Fatal("unconfirmed evidence published locally")
				}
				for _, c := range result.Result().Cookies() {
					if c.Name == "dsse_grant" {
						t.Fatal("denied callback set authorization cookie")
					}
				}
			}
		})
	}
}

func TestAuthenticationAuthorityRequiresEdgeAndIsManagementOnly(t *testing.T) {
	for _, path := range []string{"/authentication-grants/reauthentication", "/authentication-grants/mint"} {
		mux := http.NewServeMux()
		registerAuthenticationGrantAuthority(mux, grantstore.NewStore(), "", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 403 {
			t.Fatal("anonymous authority access", w.Code)
		}
		w = httptest.NewRecorder()
		dataPlaneOnlyMiddleware(mux).ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Fatal("authority exposed on data listener")
		}
	}
}

func TestRevocationReauthenticationCapabilityMustBeConfirmed(t *testing.T) {
	r, m := rolloutFixture(t)
	if e := r.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	oldFeatures := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature}
	for _, member := range m.Members {
		if e := r.authority.Record(context.Background(), member.CertificateSHA256, authrollout.Report{NodeID: member.ID, Generation: m.Generation, Version: "old", Features: oldFeatures}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	requested := append(append([]string{}, oldFeatures...), authrollout.RevocationReauthenticationFeature)
	if e := r.authority.Activate(context.Background(), m.Generation, requested, time.Now()); e == nil {
		t.Fatal("mixed fleet accepted new revocation semantics")
	}
	for _, member := range m.Members {
		if e := r.authority.Record(context.Background(), member.CertificateSHA256, authrollout.Report{NodeID: member.ID, Generation: m.Generation, Version: "new", Features: requested}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	if e := r.authority.Activate(context.Background(), m.Generation, requested, time.Now()); e != nil {
		t.Fatal(e)
	}
	if !r.featureEnabled(authrollout.RevocationReauthenticationFeature) {
		t.Fatal("confirmed feature not enabled")
	}
}

func TestAuthenticationAuthorityUnconfirmedOrDifferentEvidenceNeverBecomesLocalGrant(t *testing.T) {
	for _, mode := range []string{"unavailable", "malformed", "tenant", "subject", "scope", "auth-time", "method", "lifetime", "missing-scope-capability", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			candidate := grantstore.Grant{GrantID: "candidate", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22", AuthTime: now.Format(time.RFC3339), AMR: []string{"pwd"}}
			authority := grantstore.NewStore()
			stored, e := mintAuthenticationGrant(context.Background(), authority, candidate, time.Minute, now)
			if e != nil {
				t.Fatal(e)
			}
			leaked := atomic.Bool{}
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
			defer other.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "unavailable":
					w.WriteHeader(503)
					return
				case "malformed":
					w.Write([]byte(`{"ignored_old_response":true}`))
					return
				case "redirect":
					http.Redirect(w, r, other.URL, 307)
					return
				case "tenant":
					stored.TenantID = "other"
				case "subject":
					stored.UserID = "other"
				case "scope":
					stored.Scope = "other:22"
				case "auth-time":
					stored.AuthTime = now.Add(-time.Hour).Format(time.RFC3339)
				case "method":
					stored.AMR = []string{"unknown"}
				case "lifetime":
					stored.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
				case "missing-scope-capability":
					stored.RequiredFeatures = nil
				}
				_ = json.NewEncoder(w).Encode(authenticationGrantResponse{Grant: &stored})
			}))
			defer server.Close()
			b := &clientlessBroker{grants: grantstore.NewStore(), authority: &grantCPReporter{url: server.URL + "/grant-report", client: server.Client()}}
			if _, e := b.mintGrant(context.Background(), candidate, time.Minute, now); e == nil {
				t.Fatal("unconfirmed or substituted grant admitted")
			}
			if len(b.grants.ListAll()) != 0 {
				t.Fatal("failed authority confirmation left an allow")
			}
			if leaked.Load() {
				t.Fatal("authority redirect leaked request body")
			}
		})
	}
}

func TestPullingBrokerCannotFallbackToLocalAuthority(t *testing.T) {
	b := &clientlessBroker{grants: grantstore.NewStore(), authorityRequired: true}
	candidate := grantstore.Grant{GrantID: "candidate", TenantID: "tenant", Scope: "app:22"}
	if _, e := b.reauthenticationBoundary(context.Background(), candidate); e == nil {
		t.Fatal("missing CP channel treated as no revocation")
	}
	if _, e := b.mintGrant(context.Background(), candidate, time.Minute, time.Now()); e == nil {
		t.Fatal("local-only allow issued without authority")
	}
	if len(b.grants.ListAll()) != 0 {
		t.Fatal("missing authority left an allow")
	}
}

func TestPullingEdgeCannotAcknowledgeLocalOnlyAdministrativeRevocation(t *testing.T) {
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), ConfigSourceURL: "https://authority.example", LabMode: boolPtr(true)})
	store := theGrantStore.Load()
	if _, e := store.Mint(grantstore.Grant{GrantID: "old", TenantID: "tenant_lab_001"}, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/grants/old/revoke", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "this Edge cannot confirm") {
		t.Fatalf("Edge did not refuse authoritative write: %d %s", w.Code, w.Body)
	}
	if g, ok := store.Get("old"); !ok || g.Revoked {
		t.Fatal("rejected Edge write changed local grant")
	}
}

func TestAuthenticationAuthorityChecksExactTenantBeforeStoreAccess(t *testing.T) {
	for _, operation := range []string{"reauthentication", "mint"} {
		for _, tenant := range []string{"allowed", "other"} {
			mux := http.NewServeMux()
			registerAuthenticationGrantAuthority(mux, grantstore.NewStore(), "", func(_ *http.Request, requested string) bool { return requested == "allowed" })
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("POST", "/authentication-grants/"+operation, strings.NewReader(`{"grant":{"tenant_id":"`+tenant+`"}}`)))
			if tenant == "other" && w.Code != 403 {
				t.Fatalf("%s other tenant reached store: %d", operation, w.Code)
			}
			if tenant == "allowed" && w.Code == 403 {
				t.Fatalf("%s allowed tenant rejected", operation)
			}
		}
	}
}

func TestAuthenticationAuthorityFollowsManagementDoorNotDataDoor(t *testing.T) {
	oldSelector, oldData := controlChannelSelector.Load(), cpDataEndpoints.Load()
	t.Cleanup(func() { controlChannelSelector.Store(oldSelector); cpDataEndpoints.Store(oldData) })
	var dataRequests atomic.Int64
	data := httptest.NewServer(dataPlaneOnlyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dataRequests.Add(1)
		t.Error("authority reached data door")
	})))
	defer data.Close()
	mux := http.NewServeMux()
	registerAuthenticationGrantAuthority(mux, grantstore.NewStore(), "", func(_ *http.Request, tenant string) bool { return tenant == "tenant" })
	management := httptest.NewServer(adminSurfaceOnlyMiddleware(mux))
	defer management.Close()
	controlChannelSelector.Store(&cpEndpointSelector{current: management.URL, currentRegion: "region-a"})
	endpoints := map[string]string{"region-a": data.URL}
	cpDataEndpoints.Store(&endpoints)
	reporter := &grantCPReporter{url: data.URL + "/grant-report", client: management.Client()}
	result, err := reporter.authenticationAuthority(context.Background(), "reauthentication", authenticationGrantRequest{Grant: grantstore.Grant{TenantID: "tenant"}})
	if err != nil || result.After != "" || result.Grant != nil {
		t.Fatalf("management authority query: %+v %v", result, err)
	}
	if dataRequests.Load() != 0 {
		t.Fatal("data door used for management authority")
	}
	// A fixed single-CP deployment has no selector. Its management base must
	// remain distinct from the reporting/data URL too.
	controlChannelSelector.Store(nil)
	reporter.authorityURL = management.URL
	if _, err := reporter.authenticationAuthority(context.Background(), "reauthentication", authenticationGrantRequest{Grant: grantstore.Grant{TenantID: "tenant"}}); err != nil {
		t.Fatalf("fixed management authority query: %v", err)
	}
}
