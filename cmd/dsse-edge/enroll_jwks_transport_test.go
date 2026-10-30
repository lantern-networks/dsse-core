package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestEnrollmentJWKSHonorsConnectionAuthority(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	conn := idpregistry.Connection{JWKSURI: server.URL, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	if _, err := fetchEnrollmentJWKS(conn); err != nil {
		t.Fatalf("enrollment ignored the configured IdP authority: %v", err)
	}
	conn.CAPEM = "invalid authority"
	if _, err := fetchEnrollmentJWKS(conn); err == nil {
		t.Fatal("invalid declared authority was accepted")
	}
}

func TestEnrollmentJWKSDoesNotFollowRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := fetchEnrollmentJWKS(idpregistry.Connection{JWKSURI: redirect.URL}); err == nil {
		t.Error("redirected signing keys accepted")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("signing-key request followed an endpoint redirect")
	}
}
