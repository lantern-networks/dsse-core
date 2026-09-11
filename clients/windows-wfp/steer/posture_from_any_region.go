package main

// posture_from_any_region.go — the document that turns region failover ON must not be reachable only through
// the region that failover exists to survive.
//
// ★★★ MEASURED ON win-dev-1, 2026-08-30, with the osaka doorway stopped for four minutes.
//
// The agent boots with the bootstrap default region_failover=false and learns the real answer from the CP's
// signed steering posture. That posture was fetched from ONE address: the transport's, which is this
// organization's home region. With the home region's door down the fetch is refused, the bootstrap value
// stands, and the device never learns that failing over is permitted:
//
//	steer: CP steering-posture fetch failed (… agents.osaka…/steer/agent-policy/posture: connection refused)
//	  — keeping bootstrap flags fail_open=false region_failover=false
//
// The device then stayed dark for the whole outage — every request failed from DNS onward — and recovered at
// the second the door came back, having never tried the other region. Started while the home region was UP,
// the same binary reached region_failover=true and selected a region in under a second. The only difference
// was WHEN it started.
//
// This is the same circle as the allowed-region list being fetched from the region that is down (reported
// 2026-08-29), one level up: there the device knew it could fail over and could not find out where to; here it
// never learns that it may.
//
// ★ THE PROFILE ALREADY CARRIES THE ANSWER. transport_endpoints is the seed the operator signs — "the other
// addresses this box may start from" — and every one of them serves the same signed posture, because the
// posture is a document about the ORGANIZATION, not about a node. Asking a second address is not a widening:
// the payload is verified against the same pinned key either way, and a node that answers with a forgery is
// refused exactly as the home node would be.
//
// ★ THE HOME ADDRESS IS TRIED FIRST, ALWAYS. The ordinary case must not pay for the outage case: one dial, to
// the same place as before, and the rest of this file does nothing.

import (
	"net/url"
	"strings"
)

// posturedEndpoint is one address the steering posture may be asked for, with the name its certificate is
// verified against.
type posturedEndpoint struct {
	// BaseURL is what the fetch is issued against, e.g. https://agents.tokyo.hikari.lab:443
	BaseURL string
	// HostPort is what to dial, and ServerName is what to verify. They differ from the base URL only in that
	// the port is made explicit, which is the same normalisation the transport does.
	HostPort   string
	ServerName string
	// Region is the seed's label, for the log line. Empty for the home address, which the seed may not name.
	Region string
}

// posturePlan is the ordered list of addresses to ask for the steering posture: the address already in force
// first, then every other region the signed profile seeded, de-duplicated.
//
// explicitBase, when set (--agent-policy-url), is an operator override and is the only candidate — somebody
// who names an address is not asking for a search.
func posturePlan(explicitBase, transportHost, regionSeed string) []posturedEndpoint {
	if b := strings.TrimSpace(explicitBase); b != "" {
		e := posturedEndpointFromBase(b, "")
		return []posturedEndpoint{e}
	}
	var out []posturedEndpoint
	seen := map[string]bool{}
	add := func(e posturedEndpoint) {
		key := strings.ToLower(e.HostPort)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}
	if h := strings.TrimSpace(transportHost); h != "" {
		hp := normalisePostureHostPort(h)
		add(posturedEndpoint{BaseURL: "https://" + hp, HostPort: hp, ServerName: hostOnly(h)})
	}
	for _, entry := range strings.Split(regionSeed, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, endpoint, ok := strings.Cut(entry, "=")
		if !ok {
			// A seed may be a bare URL list; treat the whole entry as the endpoint.
			endpoint, region = entry, ""
		}
		add(posturedEndpointFromBase(strings.TrimSpace(endpoint), strings.ToLower(strings.TrimSpace(region))))
	}
	return out
}

func posturedEndpointFromBase(base, region string) posturedEndpoint {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return posturedEndpoint{}
	}
	hostport := base
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		hostport = u.Host
	} else {
		hostport = strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	}
	hp := normalisePostureHostPort(hostport)
	return posturedEndpoint{
		// The base carries the explicit port too, so the URL a log line prints is the address that was dialled.
		BaseURL:    "https://" + hp,
		HostPort:   hp,
		ServerName: hostOnly(hostport),
		Region:     region,
	}
}

// normalisePostureHostPort makes the port explicit. The deployment's profile names doors without one now that
// the agent plane is folded onto 443, and a dial target without a port is not a dial target.
func normalisePostureHostPort(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") { // IPv6 literal, possibly with a port
		if i := strings.LastIndex(h, "]"); i >= 0 && i+1 < len(h) && h[i+1] == ':' {
			return h
		}
		return h + ":443"
	}
	if strings.Contains(h, ":") {
		return h
	}
	return h + ":443"
}

func hostOnly(hostport string) string {
	h := strings.TrimSpace(hostport)
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i >= 0 {
			return h[1:i]
		}
		return h
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		return h[:i]
	}
	return h
}

// regionLabelSuffix names the seed's region in a log line, or says nothing when the seed did not label it.
func regionLabelSuffix(region string) string {
	if r := strings.TrimSpace(region); r != "" {
		return " (region " + r + ")"
	}
	return ""
}
