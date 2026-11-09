package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestARangeMatchesTheAddressesInsideIt: a network endpoint may be a range, and a Connector Access rule over it
// must match the addresses it covers — an allow over 10.47.1.0/24 allowed nothing and a deny denied nothing.
func TestARangeMatchesTheAddressesInsideIt(t *testing.T) {
	cases := []struct {
		selector  []string
		candidate string
		want      bool
	}{
		{[]string{"10.47.1.0/24"}, "10.47.1.30", true},
		{[]string{"10.47.1.0/24"}, "::ffff:10.47.1.30", true}, // a dual-stack socket's view of the same address
		{[]string{"10.47.1.0/24"}, "10.47.2.30", false},
		{[]string{"10.47.1.7/24"}, "10.47.1.200", true}, // host bits written in are the same range
		{[]string{"fd00:10::/64"}, "fd00:10::5", true},
		{[]string{"fd00:10::/64"}, "10.47.1.30", false},
		{[]string{"10.47.1.0/24"}, "h1.c.lab041.test", false}, // a name is not inside a range
		{[]string{"h1.c.lab041.test"}, "h1.c.lab041.test", true},
		{[]string{"10.47.1.30"}, "::ffff:10.47.1.30", true},
		{[]string{"\x00no-such-destination"}, "10.47.1.30", false}, // fail-closed sentinel stays closed
		// Review C3-R7: an IPv4 range written in its IPv4-mapped IPv6 form, against both spellings.
		{[]string{"::ffff:10.47.1.0/120"}, "10.47.1.30", true},
		{[]string{"::ffff:10.47.1.0/120"}, "::ffff:10.47.1.30", true},
		{[]string{"::ffff:10.47.1.0/120"}, "10.47.2.30", false},
		{[]string{"::ffff:10.47.1.0/120"}, "::ffff:10.47.2.30", false},
		// Plain IPv6 ranges keep their edges.
		{[]string{"fd00:10::/64"}, "fd00:10::ffff", true},
		{[]string{"fd00:10::/64"}, "fd00:10:0:1::1", false},
		{[]string{"10.47.1.0/24"}, "10.47.1.255", true},
		{[]string{"10.47.1.0/24"}, "10.47.0.255", false},
	}
	for _, c := range cases {
		if got := eastWestDestinationMatches(c.selector, c.candidate); got != c.want {
			t.Errorf("%v vs %q = %t, want %t", c.selector, c.candidate, got, c.want)
		}
	}
}

// TestADenyOverARangeDenies: the consequence that made this a defect. Lower priority wins; the deny over the
// range must be the rule a flow inside it meets.
func TestADenyOverARangeDenies(t *testing.T) {
	rules := []EastWestRule{
		{ID: "deny-range", Priority: 10, Destinations: []string{"10.47.1.0/24"}, Mode: "deny"},
		{ID: "allow-all", Priority: 100, Mode: "allow"},
	}
	inside := model.DecisionRequest{Destination: "10.47.1.30", ServiceFamily: "https"}
	if r, ok := MatchedEastWestRule(rules, inside); !ok || r.ID != "deny-range" {
		t.Fatalf("a flow to 10.47.1.30 met %q; the deny over 10.47.1.0/24 must apply", r.ID)
	}
	outside := model.DecisionRequest{Destination: "10.47.2.30", ServiceFamily: "https"}
	if r, ok := MatchedEastWestRule(rules, outside); !ok || r.ID != "allow-all" {
		t.Fatalf("a flow outside the range met %q", r.ID)
	}
}

// TestADenyOverAMappedRangeDenies — review C3-R7, through rule precedence as the review measured it.
func TestADenyOverAMappedRangeDenies(t *testing.T) {
	rules := []EastWestRule{
		{ID: "deny-mapped-range", Priority: 10, Destinations: []string{"::ffff:10.47.1.0/120"}, Mode: "deny"},
		{ID: "allow-all", Priority: 100, Mode: "allow"},
	}
	for _, dst := range []string{"10.47.1.30", "::ffff:10.47.1.30"} {
		if r, ok := MatchedEastWestRule(rules, model.DecisionRequest{Destination: dst, ServiceFamily: "https"}); !ok || r.ID != "deny-mapped-range" {
			t.Fatalf("a flow to %s met %q; the deny over ::ffff:10.47.1.0/120 must apply", dst, r.ID)
		}
	}
}
