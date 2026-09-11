//go:build windows

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// captive_windows.go — the Windows I/O shell for captive detection (captive_detect.go is the pure classifier).
// It issues the out-of-band connectivity-check probes from the agent's OWN process, which is self-bypassed from
// the WFP redirect (capCfg.selfImage = selfImageBypass()), so the request egresses DIRECT rather than being
// steered to the (unreachable) Edge. It resolves the check hosts via the captured UPSTREAM resolver — NOT the
// 127.0.0.1:53 tunnel proxy, which is dead exactly when we need to detect a portal — reusing newDirectResolver.
// A portal intercepting the request returns a redirect or a wrong status/body; the classifier turns that into a
// verdict, and only a POSITIVE opens the bootstrap window (a mere Edge outage with no portal stays fail-closed).

// newCaptiveProbe returns a probe func for detectCaptive, bound to a live view of the upstream resolvers. The
// upstreams are read fresh per probe so a roam to a new network uses that network's DHCP resolver.
func newCaptiveProbe(upstreams func() []string) func(captiveProbeHost) captiveProbeResult {
	return func(h captiveProbeHost) captiveProbeResult {
		var servers []string
		if upstreams != nil {
			servers = upstreams()
		}
		resolver := newDirectResolver(servers)
		dialer := &net.Dialer{Timeout: 4 * time.Second}
		tr := &http.Transport{
			Proxy: nil, // never route the probe through a system proxy
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					host, port = addr, "80"
				}
				ips, lerr := resolver.LookupHost(ctx, host)
				if lerr != nil {
					return nil, lerr
				}
				if len(ips) == 0 {
					return nil, errors.New("captive probe: no address for " + host)
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
			},
			DisableKeepAlives: true,
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   6 * time.Second,
			// Do NOT follow redirects — a 3xx off a fixed connectivity-check endpoint IS the captive signal, and
			// following it would hide the intercept behind the portal's own 200.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+h.host+h.path, nil)
		if err != nil {
			return captiveProbeResult{err: err}
		}
		resp, err := client.Do(req)
		if err != nil {
			return captiveProbeResult{err: err}
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		// Any 3xx is a redirect off the fixed endpoint (these endpoints never redirect) — the portal tell.
		redirected := resp.StatusCode >= 300 && resp.StatusCode < 400
		return captiveProbeResult{status: resp.StatusCode, body: string(body), redirected: redirected}
	}
}
