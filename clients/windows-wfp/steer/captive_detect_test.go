package main

import "testing"

func TestClassifyProbe(t *testing.T) {
	connecttest := captiveProbeHost{host: "www.msftconnecttest.com", path: "/connecttest.txt", wantStatus: 200, wantBody: "Microsoft Connect Test"}
	gen204 := captiveProbeHost{host: "connectivitycheck.gstatic.com", path: "/generate_204", wantStatus: 204}

	cases := []struct {
		name string
		h    captiveProbeHost
		r    captiveProbeResult
		want captiveVerdict
	}{
		{"connecttest expected => negative", connecttest, captiveProbeResult{status: 200, body: "Microsoft Connect Test"}, captiveNegative},
		{"connecttest login page => positive", connecttest, captiveProbeResult{status: 200, body: "<html>Please sign in</html>"}, captivePositive},
		{"connecttest wrong status => positive", connecttest, captiveProbeResult{status: 302, body: ""}, captivePositive},
		{"connecttest redirect flag => positive", connecttest, captiveProbeResult{status: 200, body: "Microsoft Connect Test", redirected: true}, captivePositive},
		{"connecttest error => unknown", connecttest, captiveProbeResult{err: errFake}, captiveUnknown},
		{"gen204 exact 204 => negative", gen204, captiveProbeResult{status: 204}, captiveNegative},
		{"gen204 got 200 portal => positive", gen204, captiveProbeResult{status: 200, body: "login"}, captivePositive},
		{"gen204 redirect => positive", gen204, captiveProbeResult{status: 302, redirected: true}, captivePositive},
		{"gen204 error => unknown", gen204, captiveProbeResult{err: errFake}, captiveUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyProbe(c.h, c.r); got != c.want {
				t.Fatalf("classifyProbe = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDetectCaptiveAggregation(t *testing.T) {
	hosts := defaultCaptiveProbeHostsWindows

	// All hosts return their expected value => negative (open network).
	if got := detectCaptive(hosts, func(h captiveProbeHost) captiveProbeResult {
		if h.wantStatus == 204 {
			return captiveProbeResult{status: 204}
		}
		return captiveProbeResult{status: 200, body: "Microsoft Connect Test"}
	}); got != captiveNegative {
		t.Fatalf("all-expected: got %v, want negative", got)
	}

	// One host intercepted => positive (short-circuits regardless of the other).
	if got := detectCaptive(hosts, func(h captiveProbeHost) captiveProbeResult {
		return captiveProbeResult{status: 200, body: "<html>hotel login</html>", redirected: true}
	}); got != captivePositive {
		t.Fatalf("intercepted: got %v, want positive", got)
	}

	// Every probe errors => unknown (indeterminate; must NOT open the window).
	if got := detectCaptive(hosts, func(h captiveProbeHost) captiveProbeResult {
		return captiveProbeResult{err: errFake}
	}); got != captiveUnknown {
		t.Fatalf("all-error: got %v, want unknown", got)
	}

	// Mixed: first errors, second returns expected => negative (a single clean expected value proves open).
	i := 0
	if got := detectCaptive(hosts, func(h captiveProbeHost) captiveProbeResult {
		i++
		if i == 1 {
			return captiveProbeResult{err: errFake}
		}
		return captiveProbeResult{status: 204}
	}); got != captiveNegative {
		t.Fatalf("mixed error+expected: got %v, want negative", got)
	}
}

// errFake is a sentinel transport error for the probe-error cases.
var errFake = fakeErr("probe failed")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
