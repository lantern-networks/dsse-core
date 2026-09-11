package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// ★ AN IdP ON AN INTERNAL AUTHORITY IS REACHABLE, AND ONLY BY THE CONNECTION THAT NAMED IT.
func TestAnIdentityProviderOnAPrivateAuthorityIsReachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	shared := &http.Client{}
	// Without the authority, the shared client cannot verify it — that is the state every deployment was in.
	if _, err := shared.Get(srv.URL); err == nil {
		t.Fatal("the test server verified against the system roots, so this proves nothing")
	}

	client, err := idpHTTPClient(shared, idpregistry.Connection{IdPID: "kc", CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("an IdP that named its own authority is still unreachable: %v", err)
	}
	resp.Body.Close()

	// A connection that names nothing keeps the shared client: the public-web case is untouched.
	if got, _ := idpHTTPClient(shared, idpregistry.Connection{IdPID: "entra"}); got != shared {
		t.Error("a connection with no authority of its own no longer uses the shared client")
	}
	// A connection naming something that holds no certificate is refused, not silently verified elsewhere.
	if _, err := idpHTTPClient(shared, idpregistry.Connection{IdPID: "bad", CAPEM: "not a certificate"}); err == nil {
		t.Error("an authority that holds no certificate was accepted")
	}
}
