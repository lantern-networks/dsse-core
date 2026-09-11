package main

import (
	"net/http"
	"sync/atomic"
)

// recovery_readiness_route.go — serving the answer to "who has no way back".
//
// ★★★ THE MEASUREMENT ALREADY EXISTED AND HAD NO READER (2026-08-25). This Edge computes, every ten minutes,
// which enrolled devices have adopted the recovery name and which have not — and the ones that have not are
// exactly the devices that cannot return if their certificate breaks or the deployment they trust changes
// underneath them. It went to this node's log and nowhere else. It was correct, and unread, for the whole of
// an outage it had been predicting by name.
//
// Nothing about the measurement changes here. What changes is that a person can ask for it before they act.
var recoveryReadinessSnapshot atomic.Pointer[func() any]

// registerRecoveryReadinessRoute serves the readiness this node has measured. Absent until the measurement
// exists, which is honest: a node that announces no recovery name has nothing to report, and reporting an
// empty answer would read as "nobody is at risk".
func registerRecoveryReadinessRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/recovery-readiness", adminEndpoint("admin.logs.read", func(w http.ResponseWriter, r *http.Request) {
		fn := recoveryReadinessSnapshot.Load()
		if fn == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"measured": false,
				"reason": "this node announces no recovery name, so no device can hold one and none is at " +
					"risk of being unable to return",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"measured": true, "readiness": (*fn)()})
	}))
}

// recoveryWayBackForReport is what this node says about the way back, for the fleet report it already sends.
//
// ★★ THE NUMBER IS "HOW MANY CANNOT RETURN", not how many can. A count of holders looks healthy while it
// climbs; the count that matters is the one somebody has to walk to, and it is the one that must be zero.
func recoveryWayBackForReport() (name string, withoutAWayBack int) {
	fn := recoveryReadinessSnapshot.Load()
	if fn == nil {
		return "", 0
	}
	r, ok := (*fn)().(recoveryNameReadiness)
	if !ok {
		return "", 0
	}
	// Silence counts as not yet, the same way the readiness line does: a machine that is switched off is
	// exactly the one this path exists for.
	unverified := map[string]bool{}
	for _, group := range [][]string{r.DoesNotHold, r.Silent, r.NeverReportedAnything, r.Contradicting, r.SerialUnverified} {
		for _, id := range group {
			unverified[id] = true
		}
	}
	return r.Name, len(unverified)
}
