package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestOIDCGeneratedIDsAreRandomizedForSameTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 24, 18, 50, 0, 0, time.UTC)
	claims := oidcValidatedClaims{
		Subject:   "user_oidc_random_001",
		Email:     "oidc-random@example.jp",
		Groups:    []string{"/dsse/admins"},
		AMR:       []string{"pwd", "otp"},
		ACR:       "urn:dsse:mfa:fresh",
		AuthTime:  now.Add(-time.Minute).UTC().Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339),
		Raw: map[string]any{
			"iss":                "https://idp.example.local/realms/lab",
			"name":               "OIDC Random",
			"preferred_username": "oidc-random",
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	config := oidcConfig{Issuer: "https://idp.example.local/realms/lab", ClientID: "dsse-edge"}

	firstAuth := authenticationEventFromOIDCClaims(config, claims, req, now, "tenant_lab_001")
	secondAuth := authenticationEventFromOIDCClaims(config, claims, req, now, "tenant_lab_001")
	if !strings.HasPrefix(firstAuth.ID, "auth_") || !strings.HasPrefix(secondAuth.ID, "auth_") || firstAuth.ID == secondAuth.ID {
		t.Fatalf("auth ids = %q, %q, want randomized auth_ ids", firstAuth.ID, secondAuth.ID)
	}
	if !strings.HasPrefix(firstAuth.SessionID, "sess_") || !strings.HasPrefix(secondAuth.SessionID, "sess_") || firstAuth.SessionID == secondAuth.SessionID {
		t.Fatalf("session ids = %q, %q, want randomized sess_ ids", firstAuth.SessionID, secondAuth.SessionID)
	}
}

func TestBuildOIDCLoginURLUsesPKCEStateAndNonce(t *testing.T) {
	loginURL, cookies, err := buildOIDCLoginURL(oidcConfig{
		Issuer:      "http://127.0.0.1:18080/realms/dsse-lab",
		ClientID:    "dsse-edge",
		RedirectURI: "http://127.0.0.1:18086/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("buildOIDCLoginURL returned error: %v", err)
	}
	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse login url: %v", err)
	}
	if parsed.Path != "/realms/dsse-lab/protocol/openid-connect/auth" {
		t.Fatalf("path = %s", parsed.Path)
	}
	query := parsed.Query()
	if query.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want code", query.Get("response_type"))
	}
	if query.Get("client_id") != "dsse-edge" {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", query.Get("code_challenge_method"))
	}
	if query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge") == "" {
		t.Fatalf("login url query missing state, nonce, or code_challenge: %s", loginURL)
	}
	cookieNames := map[string]bool{}
	for _, cookie := range cookies {
		cookieNames[cookie.Name] = true
		if !cookie.HttpOnly {
			t.Fatalf("cookie %s should be http-only", cookie.Name)
		}
	}
	for _, name := range []string{"oidc_state", "oidc_nonce", "pkce_verifier"} {
		if !cookieNames[name] {
			t.Fatalf("cookie %s missing", name)
		}
	}
}

func TestBuildOIDCLoginURLUsesExplicitAuthorizationEndpoint(t *testing.T) {
	loginURL, _, err := buildOIDCLoginURL(oidcConfig{
		Issuer:                "https://accounts.example-idp.test/tenant-001",
		ClientID:              "dsse-edge",
		RedirectURI:           "http://127.0.0.1:18086/auth/oidc/callback",
		AuthorizationEndpoint: "https://login.example-idp.test/oauth2/v2.0/authorize",
	})
	if err != nil {
		t.Fatalf("buildOIDCLoginURL returned error: %v", err)
	}
	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse login url: %v", err)
	}
	if got := parsed.String(); !strings.HasPrefix(got, "https://login.example-idp.test/oauth2/v2.0/authorize?") {
		t.Fatalf("loginURL = %s, want explicit authorization endpoint", got)
	}
	if parsed.Query().Get("client_id") != "dsse-edge" {
		t.Fatalf("client_id = %q, want dsse-edge", parsed.Query().Get("client_id"))
	}
}

func TestExchangeOIDCCodeClientAuthContract(t *testing.T) {
	cases := []struct {
		name             string
		config           oidcConfig
		wantBasicAuth    bool
		wantBodyClientID bool
	}{
		{
			name: "client_secret_basic_uses_authorization_header_only",
			config: oidcConfig{
				Issuer:        "https://issuer.example-idp.test/oauth2/default",
				ClientID:      "dsse-edge",
				ClientSecret:  "local-secret",
				RedirectURI:   "http://127.0.0.1:18086/auth/oidc/callback",
				TokenEndpoint: "https://issuer.example-idp.test/oauth2/default/v1/token",
			},
			wantBasicAuth: true,
		},
		{
			name: "public_pkce_uses_body_client_id",
			config: oidcConfig{
				Issuer:        "https://issuer.example-idp.test/oauth2/default",
				ClientID:      "dsse-public-edge",
				RedirectURI:   "http://127.0.0.1:18086/auth/oidc/callback",
				TokenEndpoint: "https://issuer.example-idp.test/oauth2/default/v1/token",
			},
			wantBodyClientID: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			oidcHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.String() != tc.config.TokenEndpoint {
					t.Fatalf("token endpoint = %s", req.URL.String())
				}
				username, password, ok := req.BasicAuth()
				if tc.wantBasicAuth {
					if !ok || username != tc.config.ClientID || password != tc.config.ClientSecret {
						t.Fatalf("basic auth = %q/%q/%v", username, password, ok)
					}
				} else if ok {
					t.Fatalf("unexpected basic auth username=%q password_present=%t", username, password != "")
				}
				if err := req.ParseForm(); err != nil {
					t.Fatalf("parse token form: %v", err)
				}
				if got := req.Form.Get("grant_type"); got != "authorization_code" {
					t.Fatalf("grant_type = %q", got)
				}
				if got := req.Form.Get("code"); got != "synthetic-auth-code-001" {
					t.Fatalf("code = %q", got)
				}
				if got := req.Form.Get("redirect_uri"); got != tc.config.RedirectURI {
					t.Fatalf("redirect_uri = %q", got)
				}
				if got := req.Form.Get("code_verifier"); got != "synthetic-verifier-001" {
					t.Fatalf("code_verifier = %q", got)
				}
				if got := req.Form.Get("client_id"); tc.wantBodyClientID && got != tc.config.ClientID {
					t.Fatalf("client_id = %q, want %q", got, tc.config.ClientID)
				} else if !tc.wantBodyClientID && got != "" {
					t.Fatalf("client_id body credential = %q, want omitted", got)
				}
				return jsonHTTPResponse(http.StatusOK, map[string]any{
					"access_token": "synthetic-access-token-001",
					"id_token":     "synthetic.id.token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}), nil
			})}
			if _, err := exchangeOIDCCode(contextForTest(), oidcHTTPClient, tc.config, "synthetic-auth-code-001", "synthetic-verifier-001"); err != nil {
				t.Fatalf("exchangeOIDCCode returned error: %v", err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestOIDCCodeExchangeAndJWKSUseExplicitProviderEndpoints(t *testing.T) {
	key := mustRSAKey(t)
	keyID := "kid-explicit-001"
	issuer := "https://issuer.example-idp.test/tenant-001"
	tokenRequests := 0
	jwksRequests := 0
	oidcHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://login.example-idp.test/oauth2/v2.0/token":
			tokenRequests++
			username, password, ok := req.BasicAuth()
			if !ok || username != "dsse-edge" || password != "local-secret" {
				t.Fatalf("basic auth = %q/%q/%v", username, password, ok)
			}
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if req.Form.Get("client_id") != "" {
				t.Fatalf("client_id body credential = %q, want omitted with client_secret_basic", req.Form.Get("client_id"))
			}
			if req.Form.Get("redirect_uri") != "http://127.0.0.1:18086/auth/oidc/callback" {
				t.Fatalf("redirect_uri = %q", req.Form.Get("redirect_uri"))
			}
			idToken := signedRS256JWT(t, key, keyID, map[string]any{
				"iss":   issuer,
				"sub":   "user_external_001",
				"aud":   []string{"dsse-edge"},
				"exp":   timeNowUnixPlus(3600),
				"nonce": "nonce-explicit-001",
				"groups": []string{
					"security-admins",
				},
				"amr": []string{"pwd", "mfa"},
			})
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"access_token": "access-token-explicit-001",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}), nil
		case "https://keys.example-idp.test/oauth2/v2.0/jwks":
			jwksRequests++
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"keys": []map[string]string{rsaPublicJWK(key, keyID)},
			}), nil
		default:
			t.Fatalf("unexpected oidc endpoint: %s", req.URL.String())
		}
		return nil, nil
	})}
	config := oidcConfig{
		Issuer:        issuer,
		ClientID:      "dsse-edge",
		ClientSecret:  "local-secret",
		RedirectURI:   "http://127.0.0.1:18086/auth/oidc/callback",
		TokenEndpoint: "https://login.example-idp.test/oauth2/v2.0/token",
		JWKSURI:       "https://keys.example-idp.test/oauth2/v2.0/jwks",
	}
	tokens, err := exchangeOIDCCode(contextForTest(), oidcHTTPClient, config, "auth-code-explicit-001", "verifier-explicit-001")
	if err != nil {
		t.Fatalf("exchangeOIDCCode returned error: %v", err)
	}
	claims, err := verifyOIDCIDToken(contextForTest(), oidcHTTPClient, config, tokens.IDToken, "nonce-explicit-001", time.Now().UTC())
	if err != nil {
		t.Fatalf("verifyOIDCIDToken returned error: %v", err)
	}
	if claims.Subject != "user_external_001" || len(claims.Groups) != 1 || claims.Groups[0] != "security-admins" {
		t.Fatalf("claims = %+v", claims)
	}
	if tokenRequests != 1 || jwksRequests != 1 {
		t.Fatalf("tokenRequests=%d jwksRequests=%d, want 1/1", tokenRequests, jwksRequests)
	}
}

func TestOIDCClaimsAppendHostedDomainSyntheticGroup(t *testing.T) {
	raw := map[string]any{
		"groups": []any{"security-admins"},
		"hd":     "corp.example",
	}
	groups, err := oidcGroupsFromClaims(oidcConfig{
		GroupsClaim:          "groups",
		HostedDomainClaim:    "hd",
		RequiredHostedDomain: "corp.example",
	}, raw)
	if err != nil {
		t.Fatalf("oidcGroupsFromClaims returned error: %v", err)
	}
	want := []string{"security-admins", "/workspace/corp.example"}
	if fmt.Sprint(groups) != fmt.Sprint(want) {
		t.Fatalf("groups = %#v, want %#v", groups, want)
	}
}

func TestOIDCClaimsRejectHostedDomainMismatch(t *testing.T) {
	_, err := oidcGroupsFromClaims(oidcConfig{
		HostedDomainClaim:    "hd",
		RequiredHostedDomain: "corp.example",
	}, map[string]any{"hd": "example.com"})
	if err == nil {
		t.Fatal("oidcGroupsFromClaims returned nil error for hosted domain mismatch")
	}
	if !strings.Contains(err.Error(), "hosted domain mismatch") {
		t.Fatalf("error = %q, want hosted domain mismatch", err.Error())
	}
}

func TestOIDCCallbackCreatesSessionAndDecisionFromHostedDomainClaim(t *testing.T) {
	key := mustRSAKey(t)
	keyID := "kid-google-hd-001"
	issuer := "https://accounts.google.com"
	oidcHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://oauth2.googleapis.com/token":
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if req.Form.Get("code") != "google-auth-code-001" || req.Form.Get("code_verifier") != "google-verifier-001" {
				t.Fatalf("form = %v", req.Form)
			}
			idToken := signedRS256JWT(t, key, keyID, map[string]any{
				"iss":   issuer,
				"sub":   "google_user_001",
				"aud":   "dsse-google-client",
				"exp":   timeNowUnixPlus(3600),
				"nonce": "google-nonce-001",
				"email": "google_user_001@corp.example",
				"hd":    "corp.example",
				"amr":   []string{"pwd", "mfa"},
			})
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"access_token": "google-access-token-001",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}), nil
		case "https://www.googleapis.com/oauth2/v3/certs":
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"keys": []map[string]string{rsaPublicJWK(key, keyID)},
			}), nil
		default:
			t.Fatalf("unexpected oidc endpoint: %s", req.URL.String())
		}
		return nil, nil
	})}

	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	evaluator.Policies = append([]model.Policy{
		{
			ID:       "pol_lab_google_workspace_https_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 35,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_google_workspace_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"user_groups": map[string]any{
					"op":     "in",
					"values": []any{"/workspace/corp.example"},
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	}, evaluator.Policies...)
	handler := newServerWithClientSecretTunnelSessionAndOIDC(evaluator, writer, connector.NewRegistry(), oidcHTTPClient, defaultConnectorSecret, tunnel.NewManager(), sessionStoreForTest(), oidcConfig{
		Issuer:               issuer,
		ClientID:             "dsse-google-client",
		RedirectURI:          "http://127.0.0.1:18090/auth/oidc/callback",
		TokenEndpoint:        "https://oauth2.googleapis.com/token",
		JWKSURI:              "https://www.googleapis.com/oauth2/v3/certs",
		HostedDomainClaim:    "hd",
		RequiredHostedDomain: "corp.example",
		HostedDomainGroup:    "/workspace/corp.example",
	})

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=google-auth-code-001&state=google-state-001", nil)
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_state", Value: "google-state-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "google-nonce-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "google-verifier-001"})
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusCreated {
		t.Fatalf("callback status = %d, want %d, body=%s", callbackRec.Code, http.StatusCreated, callbackRec.Body.String())
	}
	var session model.Session
	if err := json.NewDecoder(callbackRec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	groups := stringSliceMetadata(session.Metadata, "groups")
	if !stringSliceContains(groups, "/workspace/corp.example") {
		t.Fatalf("session groups = %#v, want /workspace/corp.example", groups)
	}
	if session.Metadata["issuer"] != issuer {
		t.Fatalf("session issuer = %#v, want %q", session.Metadata["issuer"], issuer)
	}

	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"session_id":"`+session.ID+`",
		"application_id":"app_google_workspace_https",
		"application_sensitivity":"medium",
		"destination":"dummy-private-app.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(decisionRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.PolicyID != "pol_lab_google_workspace_https_allow_001" {
		t.Fatalf("policy_id = %q, want google workspace policy", dec.PolicyID)
	}
}

func TestOIDCCallbackCreatesSessionAndGroupBoundDecision(t *testing.T) {
	key := mustRSAKey(t)
	keyID := "kid-lab-001"
	issuer := "http://issuer.example/realms/dsse-lab"
	oidcHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/realms/dsse-lab/protocol/openid-connect/token":
			username, password, ok := req.BasicAuth()
			if !ok || username != "dsse-edge" || password != "local-secret" {
				t.Fatalf("basic auth = %q/%q/%v", username, password, ok)
			}
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if req.Form.Get("code") != "auth-code-001" || req.Form.Get("code_verifier") != "verifier-001" {
				t.Fatalf("form = %v", req.Form)
			}
			idToken := signedRS256JWT(t, key, keyID, map[string]any{
				"iss":       issuer,
				"sub":       "user_lab_001",
				"aud":       []string{"dsse-edge"},
				"exp":       timeNowUnixPlus(3600),
				"auth_time": timeNowUnixPlus(-10),
				"nonce":     "nonce-001",
				"email":     "user_lab_001@example.local",
				"groups":    []string{"/security-admins"},
				"amr":       []string{"pwd", "otp"},
				"acr":       "urn:mfa:fresh",
			})
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"access_token": "access-token-001",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}), nil
		case "/realms/dsse-lab/protocol/openid-connect/certs":
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"keys": []map[string]string{rsaPublicJWK(key, keyID)},
			}), nil
		default:
			t.Fatalf("unexpected oidc path: %s", req.URL.Path)
		}
		return nil, nil
	})}

	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	evaluator.Policies = append([]model.Policy{
		{
			ID:       "pol_lab_group_mfa_https_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 40,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_group_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"user_groups": map[string]any{
					"op":     "in",
					"values": []any{"/security-admins"},
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	}, evaluator.Policies...)
	handler := newServerWithClientSecretTunnelSessionAndOIDC(evaluator, writer, connector.NewRegistry(), oidcHTTPClient, defaultConnectorSecret, tunnel.NewManager(), sessionStoreForTest(), oidcConfig{
		Issuer:       issuer,
		ClientID:     "dsse-edge",
		ClientSecret: "local-secret",
		RedirectURI:  "http://127.0.0.1:18086/auth/oidc/callback",
	})

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=auth-code-001&state=state-001", nil)
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_state", Value: "state-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "verifier-001"})
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusCreated {
		t.Fatalf("callback status = %d, want %d, body=%s", callbackRec.Code, http.StatusCreated, callbackRec.Body.String())
	}
	var session model.Session
	if err := json.NewDecoder(callbackRec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if session.UserID != "user_lab_001" || session.Metadata["mfa_state"] != "fresh" {
		t.Fatalf("session = %+v", session)
	}
	if session.Metadata["issuer"] != issuer {
		t.Fatalf("session issuer = %#v, want %q", session.Metadata["issuer"], issuer)
	}
	if !responseHasCookie(callbackRec.Result(), "session_id") {
		t.Fatalf("session_id cookie missing")
	}

	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"session_id":"`+session.ID+`",
		"actor_type":"human",
		"application_id":"app_group_https",
		"application_sensitivity":"medium",
		"destination":"dummy-private-app.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(decisionRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.PolicyID != "pol_lab_group_mfa_https_allow_001" {
		t.Fatalf("policy_id = %q, want group MFA policy", dec.PolicyID)
	}
	if dec.AuthenticationEventID == nil {
		t.Fatalf("authentication_event_id is nil")
	}
	auditLog, err := os.ReadFile(filepath.Join(logDir, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(auditLog), `"source_ip":"192.0.2.1:`) {
		t.Fatalf("audit log source_ip includes port: %s", string(auditLog))
	}
	if !strings.Contains(string(auditLog), `"source_ip":"192.0.2.1"`) {
		t.Fatalf("audit log = %s, want normalized source_ip", string(auditLog))
	}
}

func TestOIDCJWKSCacheReusesKeys(t *testing.T) {
	key := mustRSAKey(t)
	keyID := "kid-cache-001"
	issuer := "http://issuer.example/realms/" + strings.ReplaceAll(t.Name(), "/", "-")
	certFetches := 0
	oidcHTTPClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/protocol/openid-connect/certs") {
			certFetches++
			return jsonHTTPResponse(http.StatusOK, map[string]any{
				"keys": []map[string]string{rsaPublicJWK(key, keyID)},
			}), nil
		}
		t.Fatalf("unexpected oidc path: %s", req.URL.Path)
		return nil, nil
	})}
	idToken := signedRS256JWT(t, key, keyID, map[string]any{
		"iss":   issuer,
		"sub":   "user_lab_001",
		"aud":   "dsse-edge",
		"exp":   timeNowUnixPlus(3600),
		"nonce": "nonce-001",
		"amr":   []string{"pwd", "totp"},
	})
	config := oidcConfig{Issuer: issuer, ClientID: "dsse-edge"}
	if _, err := verifyOIDCIDToken(contextForTest(), oidcHTTPClient, config, idToken, "nonce-001", time.Now().UTC()); err != nil {
		t.Fatalf("first verify returned error: %v", err)
	}
	if _, err := verifyOIDCIDToken(contextForTest(), oidcHTTPClient, config, idToken, "nonce-001", time.Now().UTC()); err != nil {
		t.Fatalf("second verify returned error: %v", err)
	}
	if certFetches != 1 {
		t.Fatalf("certFetches = %d, want 1", certFetches)
	}
}

func TestOIDCCallbackStateMismatchWritesFailureAudit(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithClientSecretTunnelSessionAndOIDC(testEvaluator(), writer, connector.NewRegistry(), http.DefaultClient, defaultConnectorSecret, tunnel.NewManager(), sessionStoreForTest(), oidcConfig{
		Issuer:      "http://127.0.0.1:18080/realms/dsse-lab",
		ClientID:    "dsse-edge",
		RedirectURI: "http://127.0.0.1:18086/auth/oidc/callback",
	})
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=auth-code-001&state=bad-state", nil)
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_state", Value: "state-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-001"})
	callbackReq.AddCookie(&http.Cookie{Name: "pkce_verifier", Value: "verifier-001"})
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusUnauthorized {
		t.Fatalf("callback status = %d, want %d, body=%s", callbackRec.Code, http.StatusUnauthorized, callbackRec.Body.String())
	}
	auditLog, err := os.ReadFile(filepath.Join(logDir, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditLog), "authentication_event_failed") {
		t.Fatalf("audit log = %s, want authentication_event_failed", string(auditLog))
	}
}
