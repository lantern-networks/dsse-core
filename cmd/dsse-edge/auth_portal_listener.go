package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
)

// A browser authenticates its user at the IdP. Asking it for an endpoint's
// private key first produces a certificate chooser and an OS keychain prompt.
// Only the explicitly configured Portal name gets this separate TLS lane;
// HTTP dispatch below confines it to the browser authentication endpoints.
func browserPortalConfigFor(base *tls.Config, hello *tls.ClientHelloInfo) *tls.Config {
	if base == nil || hello == nil {
		return nil
	}
	cert := stepUpPortalCertificateFor(hello.ServerName)
	if cert == nil {
		return nil
	}
	per := base.Clone()
	per.Certificates = []tls.Certificate{*cert}
	per.GetCertificate = nil
	per.GetConfigForClient = nil
	per.ClientAuth = tls.NoClientCert
	per.ClientCAs = nil
	per.VerifyConnection = nil
	per.VerifyPeerCertificate = nil
	return per
}

func serveBrowserPortalIfNamed(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	if r == nil || r.TLS == nil || stepUpPortalCertificateFor(r.TLS.ServerName) == nil {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, r.TLS.ServerName) {
		http.Error(w, "Authentication portal host mismatch", http.StatusMisdirectedRequest)
		return true
	}
	allowed := false
	switch r.Method + " " + r.URL.Path {
	case "GET /clientless/auth/start", "POST /clientless/auth/start", "GET /clientless/auth/callback", "GET /clientless/auth/whoami",
		"POST /clientless/auth/retry":
		allowed = r.URL.RawPath == "" // no encoded-path aliases into another handler
	}
	if !allowed {
		http.NotFound(w, r)
		return true
	}
	next.ServeHTTP(w, r)
	return true
}
