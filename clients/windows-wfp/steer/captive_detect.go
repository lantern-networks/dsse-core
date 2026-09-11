package main

import "strings"

// captive_detect.go — platform-neutral captive-portal DETECTION classifier.
// A captive portal (hotel/airport/cafe Wi-Fi) intercepts HTTP to a well-known connectivity-check endpoint and
// returns a login page instead of the endpoint's fixed expected value. We probe those endpoints OUT OF BAND
// (from the self-bypassed agent process, so the probe is NOT steered) and classify the result:
//   - the expected fixed value came back  => NO portal (negative)
//   - a redirect / a different status/body => a portal is intercepting (positive)
//   - every probe errored                  => can't tell (unknown)
// Only a POSITIVE opens the bootstrap window — the third trigger condition, after netchange and Edge-unreachable:
// a mere Edge outage on an otherwise-open network stays fail-closed. Pure + injectable so it is unit-tested on any
// OS (the I/O shell that performs the real probes lives in captive_windows.go).

// captiveVerdict is the outcome of a captive-portal detection sweep.
type captiveVerdict int

const (
	captiveUnknown  captiveVerdict = iota // every probe errored — indeterminate
	captiveNegative                       // probes returned their expected fixed values — no portal
	captivePositive                       // a probe was intercepted/redirected — a portal is present
)

func (v captiveVerdict) String() string {
	switch v {
	case captiveNegative:
		return "negative"
	case captivePositive:
		return "positive"
	default:
		return "unknown"
	}
}

// captiveProbeHost is one connectivity-check endpoint with its OS-published fixed expected response. A portal
// that intercepts the request cannot reproduce this exact value, so a mismatch is the captive signal.
type captiveProbeHost struct {
	host       string // e.g. "www.msftconnecttest.com"
	path       string // e.g. "/connecttest.txt"
	wantStatus int    // expected HTTP status (204 for generate_204, 200 for connecttest)
	wantBody   string // expected body substring ("" when the status alone is the signal, e.g. 204)
}

// defaultCaptiveProbeHostsWindows are the OS/browser connectivity-check endpoints Windows itself uses. Reusing
// them means the same request that trips OUR detection also trips the OS captive detector, so the native
// "Sign in to network" flow appears once we disarm. Microsoft/Google fixed values; leak nothing.
var defaultCaptiveProbeHostsWindows = []captiveProbeHost{
	{host: "www.msftconnecttest.com", path: "/connecttest.txt", wantStatus: 200, wantBody: "Microsoft Connect Test"},
	{host: "connectivitycheck.gstatic.com", path: "/generate_204", wantStatus: 204},
}

// defaultCaptiveProbeHostsMacOS is the macOS parity set (captive.apple.com returns a fixed "Success" page).
var defaultCaptiveProbeHostsMacOS = []captiveProbeHost{
	{host: "captive.apple.com", path: "/hotspot-detect.html", wantStatus: 200, wantBody: "Success"},
}

// captiveProbeResult is what an out-of-band probe of one host observed. redirected captures the strongest
// captive tell: the transport followed (or surfaced) a cross-host 3xx to a portal, regardless of the final body.
type captiveProbeResult struct {
	status     int
	body       string
	redirected bool
	err        error
}

// classifyProbe judges a single host's probe against its expected fixed value.
//   - transport error            => unknown (this host told us nothing)
//   - redirected to a portal      => positive (the clearest intercept signal)
//   - exact expected value        => negative
//   - anything else (wrong status/body, e.g. a 200 login page where a 204 was due) => positive
func classifyProbe(h captiveProbeHost, r captiveProbeResult) captiveVerdict {
	if r.err != nil {
		return captiveUnknown
	}
	if r.redirected {
		return captivePositive
	}
	if r.status == h.wantStatus && (h.wantBody == "" || strings.Contains(r.body, h.wantBody)) {
		return captiveNegative
	}
	return captivePositive
}

// detectCaptive sweeps the hosts and aggregates. ANY intercepted host proves a portal, so a positive
// short-circuits. Otherwise a single clean expected value proves the network is open (negative). Only when every
// host errored is the result unknown. `probe` performs the real out-of-band request for one host (injected so
// this is testable; the Windows shell in captive_windows.go supplies it).
func detectCaptive(hosts []captiveProbeHost, probe func(captiveProbeHost) captiveProbeResult) captiveVerdict {
	sawNegative := false
	for _, h := range hosts {
		switch classifyProbe(h, probe(h)) {
		case captivePositive:
			return captivePositive
		case captiveNegative:
			sawNegative = true
		}
	}
	if sawNegative {
		return captiveNegative
	}
	return captiveUnknown
}
