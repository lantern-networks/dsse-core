package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
)

// a fake IdP that serves a JWKS (one RSA key) + an OIDC discovery doc echoing a configurable issuer.
func fakeIdPServer(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"abc","e":"AQAB"}]}`))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := issuerOverride
		if iss == "" {
			iss = srv.URL
		}
		_, _ = w.Write([]byte(`{"issuer":"` + iss + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + srv.URL + `/token","jwks_uri":"` + srv.URL + `/keys"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestIdPConnectionTest(t *testing.T) {
	// 1) healthy: jwks reachable with an RSA key + discovery issuer matches -> OK
	srv := fakeIdPServer(t, "")
	res := testIdPConnection(idpregistry.Connection{
		IdPID: "idp_ok", Issuer: srv.URL, JWKSURI: srv.URL + "/keys",
		AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token",
	})
	if !res.OK {
		t.Fatalf("healthy connection should test OK, got %+v", res)
	}
	if res.Checks[0].Name != "jwks" || !res.Checks[0].OK {
		t.Fatalf("jwks check should pass: %+v", res.Checks[0])
	}
	if res.Checks[1].Name != "discovery" || !res.Checks[1].OK {
		t.Fatalf("discovery check should pass: %+v", res.Checks[1])
	}

	// 2) no jwks_uri -> not OK (hard requirement)
	if r := testIdPConnection(idpregistry.Connection{IdPID: "x", Issuer: srv.URL}); r.OK {
		t.Fatal("a connection with no jwks_uri must not test OK")
	}

	// 3) jwks unreachable -> not OK
	if r := testIdPConnection(idpregistry.Connection{IdPID: "x", Issuer: srv.URL, JWKSURI: "http://127.0.0.1:1/keys"}); r.OK {
		t.Fatal("an unreachable jwks_uri must not test OK")
	}

	// 4) discovery issuer MISMATCH -> hard fail even though jwks is fine
	srv2 := fakeIdPServer(t, "https://evil.example.com")
	r := testIdPConnection(idpregistry.Connection{IdPID: "x", Issuer: srv2.URL, JWKSURI: srv2.URL + "/keys"})
	if r.OK {
		t.Fatal("a discovery issuer mismatch must fail the test")
	}
	if r.Checks[0].OK == false {
		t.Fatal("jwks should still pass on an issuer mismatch (only discovery fails)")
	}
}
