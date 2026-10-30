package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestVerifyDoorRejectsRedirectWithoutForwardingRuntimeSecret(t *testing.T) {
	var reached atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer first.Close()
	anchors := x509.NewCertPool()
	anchors.AddCert(first.Certificate())
	anchors.AddCert(other.Certificate())
	if err := askDoor(door{url: first.URL}, anchors, tls.Certificate{}, "connector-one", "runtime-secret", ""); err == nil {
		t.Fatal("redirecting door must not count another door's HTTP 200 as its own success")
	}
	if reached.Load() {
		t.Fatal("runtime secret could be sent to a redirected door")
	}
}
