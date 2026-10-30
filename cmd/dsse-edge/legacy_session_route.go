package main

import "net/http"

// A connection-balanced Edge fleet cannot route a later legacy session
// request back to the process holding its TCP socket. Refuse that transport
// explicitly in the mux-only profile; keep existing deployments unchanged.
func legacySessionRoute(muxOnly bool, legacy http.HandlerFunc) http.HandlerFunc {
	if !muxOnly {
		return legacy
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "this deployment requires CONNECT /steer-mux", http.StatusUpgradeRequired)
	}
}
