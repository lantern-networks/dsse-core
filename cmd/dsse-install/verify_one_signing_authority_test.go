package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★ THE GUARD FIRST: this check is a NEGATIVE one ("no two authorities"), and a negative check that cannot
// fail is indistinguishable from one that passes. So the two-authority case is asserted to FAIL before the
// one-authority case is asserted to pass — the deployment measured on 2026-08-25 is the first table row.
func TestTwoSigningAuthoritiesAreReported(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		wantOK   bool
		contains string
	}{
		{
			name: "two regions, two authorities — the deployment that looked healthy",
			body: `{"edges":[
				{"region_id":"region-a","cluster_id":"a","node_id":"edge-a","policy_signing_key":"33f9b9153e082e57aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{"region_id":"region-b","cluster_id":"a","node_id":"edge-b","policy_signing_key":"3350acbc94987678bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`,
			wantOK:   false,
			contains: "2 SIGNING AUTHORITIES",
		},
		{
			name: "one authority everywhere",
			body: `{"edges":[
				{"region_id":"region-a","cluster_id":"a","node_id":"edge-a","policy_signing_key":"33F9B9153E082E57aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{"region_id":"region-b","cluster_id":"a","node_id":"edge-b","policy_signing_key":"33f9b9153e082e57aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
			wantOK: true,
		},
		{
			// One node signing nothing is its own finding, not agreement with the rest.
			name: "one authority, and one node that signs nothing",
			body: `{"edges":[
				{"region_id":"region-a","cluster_id":"a","node_id":"edge-a","policy_signing_key":"33f9b9153e082e57aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{"region_id":"region-b","cluster_id":"a","node_id":"edge-b"}]}`,
			wantOK:   false,
			contains: "sign NOTHING",
		},
		{
			// The projection a customer receives carries no node facts, so this question is unanswerable —
			// and saying "unmeasured" is the only honest result. A silent empty return would read as a pass.
			name:     "a customer-scoped answer cannot be read",
			body:     `{"edges":[{"region_id":"region-a","have_applied":true,"status":"current"}]}`,
			wantOK:   false,
			contains: "NOT measured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/fleet/config-status" {
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			res := verifyOneSigningAuthority(srv.Client(), srv.URL, "token")
			if len(res) != 1 {
				t.Fatalf("want exactly one result, got %d: %#v", len(res), res)
			}
			if res[0].ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (note: %s)", res[0].ok, tc.wantOK, res[0].note)
			}
			if tc.contains != "" && !strings.Contains(res[0].note, tc.contains) {
				t.Fatalf("note does not say %q: %s", tc.contains, res[0].note)
			}
		})
	}
}

// And the case the check exists to make impossible in the first place: an unreachable authority must not be
// reported as agreement.
func TestAnUnreadableFleetViewIsNotAPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	res := verifyOneSigningAuthority(srv.Client(), srv.URL, "")
	if len(res) != 1 || res[0].ok {
		t.Fatalf("an unreadable fleet view must be reported, got %#v", res)
	}
}
