package main

import (
	"net"
	"net/http"
	"strings"
)

// A browser may attempt to reuse an HTTP/2 connection for another origin when
// the first TLS leaf covers both names. Refuse that request before the Console
// router or login gate sees it. 421 tells browsers to retry with a connection
// for the requested origin. The management leaf must still exclude Portal SANs;
// this is only a second layer for an incorrectly broad or stale certificate.
func rejectMisdirectedConsoleRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.ServerName != "" && r.Host != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if !strings.EqualFold(host, r.TLS.ServerName) {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
