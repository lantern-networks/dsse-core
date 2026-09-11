package connector

import "testing"

// TestDetectCIDRCollisionsScope proves the collision model: overlapping CIDRs collide within the same scope,
// but a differing namespace OR a differing site separates them; and a candidate that is not a CIDR (FQDN/host) is
// never in the collision domain.
func TestDetectCIDRCollisionsScope(t *testing.T) {
	existing := []CIDRRoute{
		{CIDR: "10.0.0.0/8", Namespace: "tokyo", Site: "site-tokyo", Source: "site:site-tokyo"},
	}

	cases := []struct {
		name      string
		candidate CIDRRoute
		wantHit   bool
		ambiguous bool
		relation  string
	}{
		{"equal-same-scope", CIDRRoute{CIDR: "10.0.0.0/8", Namespace: "tokyo", Site: "site-tokyo"}, true, false, "equal"},
		{"contained-same-scope", CIDRRoute{CIDR: "10.10.0.0/16", Namespace: "tokyo", Site: "site-tokyo"}, true, false, "contained_by"},
		{"superset-same-scope", CIDRRoute{CIDR: "10.0.0.0/7", Namespace: "tokyo", Site: "site-tokyo"}, true, false, "contains"},
		{"different-namespace-no-collision", CIDRRoute{CIDR: "10.0.0.0/8", Namespace: "osaka", Site: "site-tokyo"}, false, false, ""},
		{"different-site-no-collision", CIDRRoute{CIDR: "10.0.0.0/8", Namespace: "tokyo", Site: "site-osaka"}, false, false, ""},
		{"no-overlap-no-collision", CIDRRoute{CIDR: "192.168.0.0/16", Namespace: "tokyo", Site: "site-tokyo"}, false, false, ""},
		{"ambiguous-no-namespace", CIDRRoute{CIDR: "10.0.0.0/8", Site: "site-tokyo"}, true, true, "equal"},
		{"not-a-cidr-host", CIDRRoute{CIDR: "jira.internal.example.com", Namespace: "tokyo", Site: "site-tokyo"}, false, false, ""},
	}
	for _, tc := range cases {
		got := DetectCIDRCollisions(tc.candidate, existing)
		if tc.wantHit && len(got) == 0 {
			t.Errorf("%s: expected a collision, got none", tc.name)
			continue
		}
		if !tc.wantHit && len(got) != 0 {
			t.Errorf("%s: expected no collision, got %#v", tc.name, got)
			continue
		}
		if tc.wantHit {
			if got[0].Ambiguous != tc.ambiguous {
				t.Errorf("%s: ambiguous = %v, want %v", tc.name, got[0].Ambiguous, tc.ambiguous)
			}
			if got[0].Relation != tc.relation {
				t.Errorf("%s: relation = %q, want %q", tc.name, got[0].Relation, tc.relation)
			}
			if got[0].With != "10.0.0.0/8" {
				t.Errorf("%s: with_cidr = %q, want existing route", tc.name, got[0].With)
			}
		}
	}
}

// TestDetectCIDRCollisionsAmbiguousWhenExistingHasNamespace proves the ambiguous flag follows the CANDIDATE: a
// candidate with no namespace is ambiguous even when the existing route IS namespaced (the overlap cannot be
// scoped away from the candidate side), so it is still blocked by default.
func TestDetectCIDRCollisionsAmbiguousWhenExistingHasNamespace(t *testing.T) {
	existing := []CIDRRoute{{CIDR: "10.0.0.0/16", Namespace: "tokyo", Site: "site-tokyo"}}
	got := DetectCIDRCollisions(CIDRRoute{CIDR: "10.0.0.0/16"}, existing)
	if len(got) != 1 || !got[0].Ambiguous {
		t.Fatalf("expected one ambiguous collision, got %#v", got)
	}
}

// TestDetectCIDRCollisionsMultiple proves all overlapping existing routes are reported, and a non-overlapping one
// is excluded.
func TestDetectCIDRCollisionsMultiple(t *testing.T) {
	existing := []CIDRRoute{
		{CIDR: "10.0.0.0/8", Site: "s1", Source: "published_app:a"},
		{CIDR: "10.1.0.0/16", Site: "s1", Source: "published_app:b"},
		{CIDR: "172.16.0.0/12", Site: "s1", Source: "published_app:c"},
	}
	got := DetectCIDRCollisions(CIDRRoute{CIDR: "10.1.2.0/24", Site: "s1"}, existing)
	if len(got) != 2 {
		t.Fatalf("expected 2 collisions (10.0.0.0/8 + 10.1.0.0/16), got %#v", got)
	}
}
