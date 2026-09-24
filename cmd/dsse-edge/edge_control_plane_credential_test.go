package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The files that make up the Edge's machine path to its control plane. Named rather than discovered, because
// the point of the gate is to notice when a FOURTH one appears.
var edgeControlPlaneSyncFiles = []string{
	"config_bundle_sync.go",
	"steer_exclusion_sync.go",
	"enrolment_cp_report.go",
}

// Query parameters constrain a request; they do not change its permission path.
var edgeControlPlaneAdminPath = regexp.MustCompile(`"(/admin/[a-z0-9\-/]+)(?:\?[^"\r\n]*)?"`)

func TestControlPlaneCredentialRouteDiscoveryIncludesQueryParameters(t *testing.T) {
	const source = `"/admin/config-bundle" + "/admin/steer-exclusions?expected_tenant_id=" + tenant + "/admin/new-route?cursor=next"`
	matches := edgeControlPlaneAdminPath.FindAllStringSubmatch(source, -1)
	want := []string{"/admin/config-bundle", "/admin/steer-exclusions", "/admin/new-route"}
	if len(matches) != len(want) {
		t.Fatalf("found %d routes, want %d", len(matches), len(want))
	}
	for i, path := range want {
		if matches[i][1] != path {
			t.Fatalf("route %d = %q, want %q", i, matches[i][1], path)
		}
	}
}

// ★ THE SCOPE LIST HAS TO FOLLOW THE CALLS, OR IT IS A DOCUMENT (the machine-credential separation, 2026-08-16). The credential an Edge
// presents to its control plane was the shared owner secret, so nobody had ever had to know what the machine
// path actually needs. Once it is a narrow token, adding a fourth call without adding its scope produces a
// pull that fails at 3am — and the tempting fix, at 3am, is to widen the token back to owner.
//
// So this reads the sync sources for the control-plane routes they call and checks the list covers exactly
// those, in both directions: a call with no scope fails, and a scope with no call fails too.
func TestTheControlPlaneCredentialCoversExactlyTheCallsItMakes(t *testing.T) {
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore()})
	mux, ok := handler.(*http.ServeMux)
	if !ok {
		t.Skip("the admin handler is not a mux in this build")
	}

	called := map[string]bool{}
	for _, name := range edgeControlPlaneSyncFiles {
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v — the machine path moved and this gate did not", name, err)
		}
		for _, match := range edgeControlPlaneAdminPath.FindAllStringSubmatch(string(raw), -1) {
			called[match[1]] = true
		}
	}
	if len(called) == 0 {
		t.Fatal("no control-plane route was found in the sync sources, so this gate is measuring nothing")
	}

	listed := map[string]bool{}
	for _, call := range edgeControlPlaneCalls {
		listed[call.Path] = true
		if strings.TrimSpace(call.Why) == "" {
			t.Fatalf("%s is listed with no reason; a scope list nobody can argue with only grows", call.Path)
		}
		// The permission has to be the one the route is really gated on, or the token is minted for a route
		// that refuses it.
		req, err := http.NewRequest(call.Method, call.Path, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", call.Method, call.Path, err)
		}
		if _, pattern := mux.Handler(req); strings.TrimSpace(pattern) == "" {
			t.Fatalf("%s %s is in the credential list and no route serves it", call.Method, call.Path)
		}
	}

	for path := range called {
		if !listed[path] {
			t.Fatalf("the machine path calls %s and the credential does not carry a scope for it — the pull "+
				"fails in production and the tempting fix is to widen the token back to owner", path)
		}
	}
	for path := range listed {
		if !called[path] {
			t.Fatalf("the credential carries a scope for %s and nothing calls it — a permission granted for a "+
				"reason that no longer exists", path)
		}
	}
}

// And the set stays narrow: two reads and exactly one write. The property is what makes a leaked pull
// credential different from a leaked deployment, so it is asserted rather than left to review.
func TestTheControlPlaneCredentialCarriesOneWriteAndNoPlatformPowers(t *testing.T) {
	scopes := edgeControlPlaneScopes()
	sort.Strings(scopes)

	writes := 0
	for _, scope := range scopes {
		if strings.HasSuffix(scope, ".write") {
			writes++
		}
		for _, forbidden := range []string{"admin.platform.write", "admin.tenant.admin", "admin.quota.write", "admin.api_tokens.write", "admin.certs.write"} {
			if scope == forbidden {
				t.Fatalf("the machine credential carries %s — a compromised Edge would own the deployment", scope)
			}
		}
	}
	if writes != 1 {
		t.Fatalf("the machine credential carries %d write scopes (%v); it reports enrolments and reads its "+
			"own configuration, and every additional write is something a compromised Edge can do", writes, scopes)
	}
}
