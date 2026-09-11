package main

import (
	"fmt"
	"net/http"
	"strings"
)

// verify_console.go — the fourth step of the install order, and whether it reaches the right node.
//
// ★★★ THE INSTALLER SKIPPED STRAIGHT FROM THE CONTROL PLANE TO THE EDGES (2026-08-23). The order is Postgres,
// the anchor, the control plane, the CONSOLE, then the Edges — and everything generated here went from the
// third to the fifth. A deployment nobody can administer except with curl is not one anybody hands over.
//
// ★★★ AND THE CONSOLE IS DENY-BY-DEFAULT, WHICH CHANGES WHAT "IT ANSWERS" MEANS. Every gated asset is refused
// without a session, so /healthz answers 401 — the server is up and the gate is working. A check that read
// that as "down" would report a correct deployment as broken, and one that demanded 200 would be demanding
// the SPA be handed to an unauthenticated client, which is the thing the gate exists to prevent.
func verifyConsole(client *http.Client, consoleURL string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}
	consoleURL = strings.TrimRight(strings.TrimSpace(consoleURL), "/")
	if consoleURL == "" {
		return out
	}

	code, _, err := get(client, consoleURL+"/", "")
	if err != nil {
		add("the Console answers", false, "%s -> %v", consoleURL, err)
		return out
	}
	add("the Console answers", true, "%s -> %d", consoleURL, code)

	// The gate, asked with the request it exists to refuse: a gated asset with no session.
	gated, _, gerr := get(client, consoleURL+"/app.js", "")
	switch {
	case gerr != nil:
		add("the Console refuses an unauthenticated request", false, "could not ask: %v", gerr)
	case gated == 200:
		add("the Console refuses an unauthenticated request", false,
			"a gated asset was served with no session (200). The admin application is handed to anybody who "+
				"asks, and every check after this one is about a deployment that has already lost")
	default:
		add("the Console refuses an unauthenticated request", true, "answered %d with no session", gated)
	}

	// ★★★ WHERE SIGN-IN LANDS, ASKED THROUGH THE CONSOLE. Measured on the lab tonight: /admin/login/password
	// answers 401 on the control plane and 404 on an Edge, because first-party accounts are the control
	// plane's and an Edge has no such route at all. So a deliberately-wrong password, sent through the
	// Console, says which kind of node is behind its auth surface without needing a credential that works.
	//
	// ★ IT DOES NOT ESTABLISH WHERE READS GO. ADMIN_API_UPSTREAM is a separate setting and everything behind
	// it is gated, so nothing outside can see it without a session. Said here rather than implied: this check
	// is about the auth surface, and a deployment can still point its reads at an Edge with this passing.
	code, body, err := post(client, consoleURL+"/admin/login/password", "",
		[]byte(`{"email":"dsse-install-verification@invalid","password":""}`))
	switch {
	case err != nil:
		add("the Console's sign-in reaches a node that can authenticate", false, "could not ask: %v", err)
	case code == 404:
		add("the Console's sign-in reaches a node that can authenticate", false,
			"sign-in answered 404, which is what an EDGE answers — it has no first-party account routes at "+
				"all, so nobody can log in to this deployment. The auth surface belongs to the control plane")
	case code == 401 || code == 400 || code == 422:
		add("the Console's sign-in reaches a node that can authenticate", true,
			"a deliberately-invalid sign-in was refused (%d), which is a node that HAS accounts", code)
	default:
		add("the Console's sign-in reaches a node that can authenticate", false,
			"sign-in answered %d (%s)", code, first(body, 100))
	}
	return out
}
