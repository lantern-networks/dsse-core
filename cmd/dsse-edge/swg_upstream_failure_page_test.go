package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func certificateFailure() error {
	return &url.Error{Op: "Get", URL: "https://idp.example.test/realms/x/protocol/openid-connect/auth?client_id=c&state=s",
		Err: x509.UnknownAuthorityError{}}
}

func TestABrowserGetsAPageNotJSONWhenTheUpstreamCertificateFails(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.test/realms/x/protocol/openid-connect/auth", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "ja,en;q=0.8")
	w := httptest.NewRecorder()
	writeSWGUpstreamFailure(w, r, "idp.example.test", certificateFailure())
	body := w.Body.String()
	if w.Code != http.StatusBadGateway || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status %d, content type %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, leak := range []string{"x509", "client_id=", "state=", "{\"error\""} {
		if strings.Contains(body, leak) {
			t.Errorf("the page shows %q to the person at the browser:\n%s", leak, body)
		}
	}
	if !strings.Contains(body, "社内サイトの証明書") {
		t.Errorf("the page does not say where an administrator fixes it:\n%s", body)
	}
}

func TestANonBrowserGetsTheSentenceAsJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.test/x", nil)
	w := httptest.NewRecorder()
	writeSWGUpstreamFailure(w, r, "idp.example.test", certificateFailure())
	if !strings.Contains(w.Body.String(), "Internal site certificates") || strings.Contains(w.Body.String(), "x509") {
		t.Fatalf("JSON answer: %s", w.Body.String())
	}
}

func TestOtherUpstreamFailuresKeepTheirAnswer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	w := httptest.NewRecorder()
	writeSWGUpstreamFailure(w, r, "example.test", errors.New("connection refused"))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "connection refused") {
		t.Fatalf("a non-certificate failure changed: %d %s", w.Code, w.Body.String())
	}
}

// Found 2026-11-06: a failure that is not a certificate's keeps its JSON answer, whatever words the
// URL carries.
func TestTheURLsWordsDoNotMakeAFailureACertificateOne(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.test/certificate-information", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	err := &url.Error{Op: "Get", URL: "https://example.test/certificate-information", Err: errors.New("remote error: tls: handshake failure")}
	writeSWGUpstreamFailure(w, r, "example.test", err)
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || strings.Contains(w.Body.String(), "Internal site certificates") {
		t.Fatalf("a handshake failure was answered as a certificate one because of the URL: %s", w.Body.String())
	}
}

func TestAWrappedVerificationErrorIsACertificateFailure(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://idp.example.test/x", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}
	if !upstreamCertificateVerificationFailed(err) {
		t.Fatal("a verification error inside a url.Error was not recognised")
	}
}
