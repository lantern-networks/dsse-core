package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★ THE EDGE CANNOT SERVE ACCOUNT WORK, AND THE FRONT DOOR IS THE ONLY THING THAT KNOWS (2026-08-18).
//
// First-party admin accounts are minted, stored and authenticated on the control plane. The Edge is not
// started with -first-party-accounts and has no account store at all:
//
//	GET /admin/admins on the Edge -> 503 {"error":"first-party admin accounts are not enabled"}
//	GET /admin/admins on the CP   -> 200 {"admins":[...]}
//
// The Console reaches the admin API through its own front door, which sends /admin/* to the Edge and then
// OVERRIDES a hand-written list of auth-surface prefixes to the control plane. That list is what keeps the
// Administrators screen working, and it is a list somebody has to remember to extend: an account route added
// tomorrow lands on the Edge and answers 503, on a screen whose whole subject is who may administer a tenant.
//
// (Measured before writing this: the screen is NOT broken today. The direct-to-Edge 503 is real and is not the
// path the Console takes — an earlier draft of this commit claimed a customer-visible outage on the strength
// of the 503 alone, which was a measurement of the wrong door.)
func TestTheFrontDoorSendsEveryAccountRouteToTheAuthAuthority(t *testing.T) {
	src, err := os.ReadFile("admin_auth_store.go")
	if err != nil {
		t.Fatalf("read the account routes: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	route := regexp.MustCompile(`mux\.HandleFunc\("(?:GET|POST|PUT|DELETE|PATCH) (/admin/[^"]+)"`)

	// A handler is an account route when it refuses without the first-party store. suspend/reactivate share a
	// handler, so the scan finds their siblings and they are covered by the same /admin/admins/ subtree.
	paths := map[string]bool{}
	current, start := "", 0
	for i, l := range lines {
		if m := route.FindStringSubmatch(l); m != nil {
			current, start = m[1], i
		}
		if current != "" && strings.Contains(l, "LocalCredentials == nil") && i-start < 60 {
			paths[current] = true
			current = ""
		}
	}
	if len(paths) < 4 {
		t.Fatalf("only %d account routes found — this gate is reading the wrong file", len(paths))
	}

	door, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "reference", "console-server", "main.go"))
	if err != nil {
		t.Skipf("console front door not readable from here: %v", err)
	}
	// ONLY the override slice, not every /admin/ literal in the file. The base route `mux.Handle("/admin/",
	// edgeProxy)` is itself a trailing-slash pattern, so scanning the whole file makes every path look covered
	// — including the enforcement surface, which is what the control below is there to catch. It caught it.
	block := regexp.MustCompile(`(?s)authProxy != nil.*?\n\t\}`).FindString(string(door))
	if block == "" {
		t.Fatal("could not find the front door auth-surface override list — the gate is reading the wrong shape")
	}
	patterns := regexp.MustCompile(`"(/[^"]*)"`).FindAllStringSubmatch(block, -1)
	if len(patterns) < 5 {
		t.Fatalf("the override list holds %d patterns, which is too few to be the real one", len(patterns))
	}
	covered := func(p string) bool {
		// Go's ServeMux matches a trailing-slash pattern as a subtree, so "/admin/admins/" covers every
		// per-principal route beneath it. Anything else must appear literally.
		for _, prefix := range patterns {
			pat := prefix[1]
			if pat == p {
				return true
			}
			if strings.HasSuffix(pat, "/") && strings.HasPrefix(p, pat) {
				return true
			}
		}
		return false
	}
	var missing []string
	for p := range paths {
		// {principal_id} is a Go 1.22 wildcard on the Edge; the front door matches by prefix, so compare the
		// literal segment before it.
		probe := p
		if i := strings.Index(p, "/{"); i >= 0 {
			probe = p[:i] + "/x"
		}
		if !covered(probe) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the front door sends these to the Edge, which answers 503 because it has no account store: %v",
			missing)
	}

	// ★ THE CONTROL: the override list must NOT swallow the enforcement surface. If /admin/ itself were
	// overridden, every read about what is actually being enforced would come from the control plane's copy of
	// what it last distributed — the opposite mistake, and the harder one to notice.
	for _, edgeOwned := range []string{"/admin/pki/certificates", "/admin/steer-exclusions", "/admin/rules"} {
		if covered(edgeOwned) {
			t.Fatalf("%q is routed to the auth authority; it is the enforcing node's answer", edgeOwned)
		}
	}
}
