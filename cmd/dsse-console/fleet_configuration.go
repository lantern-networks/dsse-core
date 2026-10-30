package main

import (
	"net/http"
	"path"
	"strings"
)

// Machine distribution does not pass through the browser-facing Console, even
// for an operator session. The CP independently authorizes the direct Edge read.
func withoutFleetConfigurationProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		p = strings.TrimPrefix(p, "/control")
		if p == "/admin/config-bundle" || p == "/admin/authentication-grants" {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
