package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ BOTH SWG EGRESS HANDLERS MUST DIAL THE ORIGIN THE SAME WAY (2026-08-18).
//
// The edge builds two handlers from the same config: an in-process one for a decrypted flow handed over by the
// interceptor, and the external /swg/http-egress route the agents POST to. They differ in AUTHORIZATION — the
// external route is connector-gated — and they must never differ in EGRESS ENGINE, because the origin does not
// care how the caller authenticated.
//
// They did. The browser-faithful engine (curl-impersonate, and with it the AIA chasing that fetches a missing
// cross-signed link) was assigned to the in-process handler ONLY, on the reading that the macOS NE / Windows
// WFP decrypt-all egress is served in process. It is not: the NE's decrypt-and-forward arrives over the wire at
// /swg/http-egress — which is why the request carries an NE-runtime header whose value is literally
// "runtime_copy_lab_tls". So every steered device egressed through Go, and the browser-faithful engine ran for
// a path that carries almost nothing.
//
// Measured: partner.microsoft.com returned the edge's own 502 to a steered browser on two operating systems,
// with a Go crypto/tls error, while the same URL through the broker returned 301 and the engine's log showed it
// had already chased and kept the missing link. Every AIA-dependent origin, and every bot-mitigated one, was
// unreachable through the product while being fine in a plain browser.
//
// This is a source check because the assignment lives in a function far too large to construct in a test. It is
// deliberately about the PAIRING rather than about any one client: whatever the device handler egresses with,
// the external route egresses with too.
func TestBothSWGEgressHandlersGetTheSameEgressClient(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	source := string(raw)

	// The browser-faithful branch must assign the engine to BOTH handlers. Scoped to that branch on purpose:
	// when the engine is off there is nothing to pair, and the external route keeps the client the deployment
	// handed in (several tests depend on being able to hand one in).
	start := strings.Index(source, "if config.SWGEgressBrowserMimic {")
	if start < 0 {
		t.Fatal("the browser-faithful branch is gone — this gate has stopped seeing the wiring")
	}
	branch := source[start:]
	if end := strings.Index(branch, "\n\t} else {"); end > 0 {
		branch = branch[:end]
	}
	if !strings.Contains(branch, "swgEgressDeviceConfig.ProxyClient = &mimicClient") {
		t.Fatal("the in-process handler no longer gets the browser-faithful client")
	}
	if !strings.Contains(branch, "swgEgressConfig.ProxyClient = &mimicClient") {
		t.Fatal("the external /swg/http-egress route does NOT get the browser-faithful client.\n\n" +
			"That is where the agents arrive — the NE's decrypt-and-forward posts there, which is why the " +
			"request carries an NE-runtime header whose value is \"runtime_copy_lab_tls\". Assigned to the " +
			"in-process handler alone, every steered device egresses through Go: no AIA chasing, so an origin " +
			"whose chain needs a cross-signed link is unreachable through the product while fine in a plain " +
			"browser, and no browser-faithful TLS, so bot-mitigated origins fail the same way.")
	}

	// ★ AND THE EXTERNAL HANDLER MUST BE BUILT AFTER THE CHOICE. It captures its config BY VALUE, so building it
	// first keeps the plain Go client whatever the branch then assigns — which is how the bug survived being
	// looked at: the assignment was right there, several lines below a handler that had already been made.
	assignment := strings.Index(source, "swgEgressConfig.ProxyClient =")
	construction := strings.Index(source, "swgHTTPEgressHandler := newEdgeSWGHTTPEgressHandler(swgEgressConfig)")
	if assignment < 0 || construction < 0 {
		t.Fatal("the external handler's construction or its egress assignment is gone — this gate no longer measures anything")
	}
	if construction < assignment {
		t.Fatal("the external /swg/http-egress handler is constructed BEFORE its egress client is chosen. " +
			"newEdgeSWGHTTPEgressHandler takes its config by value, so the handler keeps whatever client the " +
			"config held at that moment and every later assignment is dead.")
	}
}
