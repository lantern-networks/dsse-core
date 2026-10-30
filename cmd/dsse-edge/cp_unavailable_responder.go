package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"time"
)

func registerCPUnavailableFlag() *string {
	return flag.String("cp-unavailable-listen", "", "serve only HTTPS 503 refusals for the region admin doorway when no real CP accepts traffic; no authority or forwarding")
}

// A passive HTTPS refusal endpoint behind the region's admin SNI route. It has
// no database, credentials, policy, signing authority or forwarding capability.
// HAProxy reaches it only when every real CP fails its leader/quorum check.
func cpUnavailableHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no accepting control-plane is available; retry shortly"})
}

func serveCPUnavailable(addr, cert, key string) error {
	if cert == "" || key == "" {
		return fmt.Errorf("CP unavailable responder requires its deployment TLS certificate and key")
	}
	s := &http.Server{
		Addr: addr, Handler: http.HandlerFunc(cpUnavailableHandler),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return s.ListenAndServeTLS(cert, key)
}
