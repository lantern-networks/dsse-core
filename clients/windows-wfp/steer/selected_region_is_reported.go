package main

// selected_region_is_reported.go -- a device has to say which region it is actually on, not only which one it
// was pointed at.
//
// ★★★ MEASURED 2026-08-30. The start-up banner names home= from the profile. nearest-healthy then picks
// whichever seeded region answers fastest, which on this box was the OTHER one. The peer dropped the home
// region, this device carried on without losing a single request, and that read as a perfect zero-loss
// failover. It was a device that had never been in the region that went down.
//
// ★ THE AGENT DID SAY SO -- ON STDERR. region_failover lines go through log.Printf (stderr); the flow lines
// this box's measurement script was reading go to stdout. "steering through region \"tokyo\" -- selected
// nearest healthy allowed region" was written at 12:22:02, one line, in the stream nobody opened. Two wrong
// diagnoses were published from the other stream before anyone looked.
//
// So this is NOT here because the information was missing. It is here because the ONE line that decides
// whether a measurement means anything was indistinguishable from sixty lines of scheduler chatter, in a
// second stream, and said "tokyo" without saying that tokyo is not this device's home. An operator reading
// one line has to be able to tell. The fix is the emphasis and the home comparison, not the fact.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// reportSelectedRegion waits for the region engine's first selection and states it, saying plainly whether it
// is the home region or another one.
//
// ★ It reports the DIAL TARGET, not a name. The names in this system are static -- the profile's transport_url
// is one string for the life of the install -- so a log line built from a name says nothing about where the
// packets go. A URL that reads "osaka" while every dial goes to tokyo is not a hypothetical: it was published
// as a root cause on 2026-08-30 and had to be withdrawn.
func reportSelectedRegion(ctx context.Context, tc transportConfig, home string) {
	if tc.active == nil {
		return
	}
	// The engine's first selection lands within a probe round or two. Report the moment there is one, then stop:
	// every LATER change is narrated by switchTo, which is where a change belongs.
	deadline := time.After(90 * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			fmt.Printf("steer: ★ region-failover selected no region within 90s — this device is dialling its "+
				"bootstrap endpoint and has not been told it may move. home=%q\n", home)
			return
		case <-tick.C:
			ae := tc.active.Load()
			if ae == nil || (len(ae.dialAddrs) == 0 && ae.host == "") {
				continue
			}
			where := strings.Join(ae.dialAddrs, ",")
			if where == "" {
				where = ae.host
			}
			fmt.Printf("steer: ★ steering through region %s — dialling %s (verifying %q)\n",
				describeSelection(ae.host, home), where, ae.serverName)
			return
		}
	}
}

// describeSelection says whether the endpoint in force is the home one, in the words an operator reading a
// single line needs: "home" alone would hide the case this exists for.
func describeSelection(activeHost, home string) string {
	a := strings.TrimSpace(activeHost)
	h := strings.TrimSpace(home)
	if a == "" {
		return fmt.Sprintf("(none yet; home=%q)", h)
	}
	if h != "" && strings.Contains(strings.ToLower(a), strings.ToLower(h)) {
		return fmt.Sprintf("%q — the HOME region", a)
	}
	return fmt.Sprintf("%q — NOT the home region (home=%q); nearest-healthy chose this one", a, h)
}

// describeUpstreams names the resolvers an out-of-band lookup was given, so a failure to resolve is a fact
// somebody can act on rather than a bare "could not resolve".
func describeUpstreams(direct []string) string {
	var usable []string
	for _, s := range direct {
		s = strings.TrimSpace(s)
		// The same two the resolver itself drops: querying the loopback proxy is the cycle being broken.
		if s == "" || s == "127.0.0.1" || s == "::1" {
			continue
		}
		usable = append(usable, s)
	}
	if len(usable) == 0 {
		return "none from this box (the loopback proxy is never queried here) + the public fallback"
	}
	return strings.Join(usable, ",") + " + the public fallback"
}

func emptyAs(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}
