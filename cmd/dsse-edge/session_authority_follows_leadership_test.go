package main

import (
	"strings"
	"testing"
)

// ★★★ ADMINISTRATION DIED WHEN LEADERSHIP MOVED (2026-08-25, reported from a real endpoint and reproduced).
//
// The Edge asks the authority who a caller is at a FIXED url — its own region's internal control-plane door,
// which routes to whichever LOCAL control plane leads. With leadership in another region that door has no
// healthy backend, so every admin request landing on this Edge answered
//
//	500 {"error":"admin authentication store is unavailable"}
//
// with a perfectly good token and a control plane that had not restarted. Minutes later the same token
// answered 200, which is the worst kind of intermittent: it reads as a flaky credential.
func TestSessionIntrospectionFollowsTheLeader(t *testing.T) {
	s := &sessionIntrospector{url: "https://dsse-control-plane:9443/admin/session"}

	// No list configured — a single-region deployment — keeps the configured door. Its one door IS the answer.
	controlChannelSelector.Store(nil)
	if got := s.currentURL(); got != s.url {
		t.Fatalf("with no endpoint list the configured authority was replaced: %q", got)
	}

	// Leadership elsewhere: the host follows, the PATH does not. Sending /admin/session to the wrong path
	// would answer 404 and read as "this token is unknown".
	sel := &cpEndpointSelector{regions: []string{"region-a", "region-b"}}
	sel.current = "https://agents.example:10643"
	controlChannelSelector.Store(sel)
	got := s.currentURL()
	if !strings.HasPrefix(got, "https://agents.example:10643") {
		t.Fatalf("the introspection did not follow leadership: %q", got)
	}
	if !strings.HasSuffix(got, "/admin/session") {
		t.Fatalf("following leadership lost the path, so the authority would answer 404: %q", got)
	}

	// Connected to nothing: fall back to the configured door rather than to an empty address.
	sel.current = ""
	if got := s.currentURL(); got != s.url {
		t.Fatalf("with no current leader the introspection went somewhere other than its configured door: %q", got)
	}
	controlChannelSelector.Store(nil)
}
