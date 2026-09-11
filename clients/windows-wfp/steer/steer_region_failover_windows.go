//go:build windows

// steer_region_failover_windows.go — the Windows I/O the portable region-failover driver (steer_region_failover.go)
// is missing: a REAL health probe (out-of-band resolve + TCP + (T) mTLS handshake, with admission classification)
// and the live endpoint SWAP (one atomic Store into transportConfig.active that repoints every consumer). The
// selection/hysteresis/fail-closed logic is NOT here — it is in the engine, by design.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

// parseRegionEndpoint splits a region endpoint URL ("https://host:port" or "wss://host:port") into the dial host,
// port, and the SNI/pinned name to verify. Defaults to :443 when no port is given (matching the (T) transport).
func parseRegionEndpoint(endpoint string) (host, port, serverName string, err error) {
	u := strings.TrimSpace(endpoint)
	switch {
	case strings.HasPrefix(u, "https://"):
		u = strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "wss://"):
		u = strings.TrimPrefix(u, "wss://")
	default:
		return "", "", "", fmt.Errorf("region endpoint %q must be https:// or wss://", endpoint)
	}
	u = strings.TrimRight(u, "/")
	if i := strings.IndexAny(u, "/"); i >= 0 {
		u = u[:i] // drop any path
	}
	h, p, e := net.SplitHostPort(u)
	if e != nil {
		h, p = u, "443"
	}
	if strings.TrimSpace(h) == "" {
		return "", "", "", fmt.Errorf("region endpoint %q has no host", endpoint)
	}
	return h, p, h, nil
}

// resolveRegionAddrs returns the "ip:port" dial targets for a region's host. An IP literal is returned verbatim;
// a HOSTNAME is resolved OUT OF BAND (direct/public resolver, never the loopback DNS proxy — that proxy rides the
// very tunnel we may be re-establishing). Empty result => the host could not be resolved (treat as unreachable).
func resolveRegionAddrs(host, port string, directServers []string) []string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{net.JoinHostPort(addr.Unmap().String(), port)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := newDirectResolver(directServers).LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		if a, e := netip.ParseAddr(ip); e == nil {
			s := net.JoinHostPort(a.Unmap().String(), port)
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// newWindowsRegionProbe builds the engine Probe: for each region endpoint it resolves out of band, TCP-connects,
// and does a (T) mTLS handshake against the SHARED pinned transport CA using this device's client cert (the same
// pin/cert as the live tunnel; only the SNI/target change per region). Classification:
//   - TCP connect/handshake timeout or refusal           -> Reachable:false              (region down)
//   - handshake OK                                        -> Reachable:true, Admitted:true, RTT measured
//   - server REJECTS our device cert (revoked/not-enrolled, a "remote error: tls:" admission alert)
//     -> Reachable:true, Admitted:false  (deny, not a health failure)
//   - any other handshake error (incl. our CA pin rejecting their cert) -> Reachable:false (not a usable Edge)
//
// upstreams supplies the box's real resolvers to prefer for out-of-band resolution (nil = public fallback).
func newWindowsRegionProbe(tc transportConfig, connectTimeout time.Duration, upstreams func() []string) regionfailover.Probe {
	if connectTimeout <= 0 {
		connectTimeout = 2 * time.Second
	}
	return func(ep regionfailover.RegionEndpoint) regionfailover.Health {
		host, port, serverName, err := parseRegionEndpoint(ep.Endpoint)
		if err != nil {
			return regionfailover.Health{} // unusable endpoint = unreachable
		}
		var direct []string
		if upstreams != nil {
			direct = upstreams()
		}
		addrs := resolveRegionAddrs(host, port, direct)
		if len(addrs) == 0 {
			return regionfailover.Health{Reachable: false}
		}
		start := time.Now()
		raw, err := net.DialTimeout("tcp", addrs[0], connectTimeout)
		if err != nil {
			// ★ SAID OUT LOUD. "Unreachable" with no reason is what let a probe misclassify two healthy
			// regions for seventy seconds while the tunnel beside it worked (2026-08-30). A refusal, a
			// timeout and a pin failure are three different faults with three different fixes, and the
			// engine's decision is only as good as this classification.
			probeLogf("region_failover probe: region %q at %s is UNREACHABLE — TCP dial failed: %v",
				ep.Region, addrs[0], err)
			return regionfailover.Health{Reachable: false}
		}
		defer raw.Close()
		// Fresh tls.Config per probe (no session cache): a resumed session would skip the chain check AND mask an
		// admission change, both of which we must observe honestly here.
		cfg := regionProbeTLSConfig(tc, serverName)
		tconn := tls.Client(raw, cfg)
		_ = tconn.SetDeadline(time.Now().Add(connectTimeout))
		herr := tconn.Handshake()
		rtt := time.Since(start)
		if herr == nil {
			_ = tconn.Close()
			return regionfailover.Health{Reachable: true, Admitted: true, RTT: rtt}
		}
		if isAdmissionRejection(herr) {
			probeLogf("region_failover probe: region %q at %s ADMITTED this device NO — the Edge rejected the "+
				"client certificate (%v). The region is up; this device is not welcome there.", ep.Region, addrs[0], herr)
			return regionfailover.Health{Reachable: true, Admitted: false, RTT: rtt}
		}
		// ★ EVERYTHING ELSE IS REPORTED AS unreachable, AND THAT IS THE CLASS THAT HID THE 2026-08-30 DEFECT:
		// an x509 failure here means the Edge is answering and this device cannot verify what it served --
		// which is a TRUST or SNI fault, not a dead region, and it takes a completely different fix. Naming
		// the name that was sent is the whole diagnosis when it is one.
		probeLogf("region_failover probe: region %q at %s is treated as UNREACHABLE — the handshake failed "+
			"presenting name %q: %v. If that is a certificate-verification error the region is UP and this "+
			"device could not verify what it served.", ep.Region, addrs[0], probeSNI(tc, serverName), herr)
		return regionfailover.Health{Reachable: false}
	}
}

// isAdmissionRejection reports whether a TLS handshake error is the SERVER rejecting THIS device's cert
// (revoked / not-enrolled) — a "remote error: tls:" alert about the certificate or access. That is a deny to
// surface, distinct from the region being unreachable or our own CA pin rejecting their cert (x509: ...).
func isAdmissionRejection(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	if !strings.Contains(s, "remote error: tls:") {
		return false // a LOCAL error (e.g. x509 pin failure, timeout) is not an admission signal
	}
	for _, kw := range []string{"certificate", "access denied", "revoked", "unknown", "expired", "required", "denied"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// windowsRegionActions implements the driver's side effects on the live transport. switchTo is the only one that
// mutates state (an atomic endpoint Store every consumer follows); the deny/connect hooks log, because with
// region failover the agent runs fail-CLOSED (no --fail-open), so "no healthy region" is denied structurally —
// the redirect stays up and dials to the unreachable in-boundary endpoint simply fail (never a bypass).
type windowsRegionActions struct {
	active *atomic.Pointer[activeEndpoint]
	// onEndpoint, when set, is handed the dial addresses the device has just moved to, so the capture's
	// destination bypass can follow the region.
	//
	// ★★★ IT DID NOT FOLLOW (2026-08-30). The Edge destination bypass is filled in once at arm time from the
	// CONFIGURED transport host, and the refresher that keeps it current is gated on region failover being
	// OFF (main_windows.go: "if !*regionFailoverOn && transportHostIsName"). So a device that failed over had
	// a loop guard naming the region it had LEFT, and its tunnel to the new region was protected by the AppID
	// self-exclusion alone -- the very arrangement the guard exists because we do not want to rely on.
	onEndpoint func(addrs []string)
	upstreams  func() []string
	logf       func(string, ...any)
}

// ★★★ IT SAYS WHAT IT REFUSED TO DO, AND WHY (2026-08-30, measured across two region outages on win-dev-1).
//
// The selection and the demotion were already narrated -- on stderr, through log.Printf, while the flow lines
// go to stdout. What was NOT written down is this function's refusal path, which is the one that decides
// whether the device can move at all: "could not resolve out of band" returned an error to the engine and
// said nothing to anybody, while keeping the PRIOR endpoint -- during an outage, the dead one.
//
// So the device goes on dialling a region that is gone, for as long as the outage lasts, and the only trace
// is an absence. That is indistinguishable from "failover is not implemented" unless it is said out loud,
// and it names the resolvers it was given because out-of-band resolution deliberately refuses the loopback
// proxy: an empty upstream list is exactly how a device stays on a dead region while believing it may move.
//
// ★ THE REFUSAL PATH IS THE ONE THAT MATTERS MOST. "Could not resolve out of band" keeps the PRIOR endpoint,
// which under an outage is the dead one -- so the device goes on dialling a region that is gone, silently,
// for as long as the outage lasts. That is indistinguishable from "failover is not implemented" unless it is
// said out loud.
func (a *windowsRegionActions) switchTo(ep regionfailover.RegionEndpoint) error {
	logf := a.logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	host, port, serverName, err := parseRegionEndpoint(ep.Endpoint)
	if err != nil {
		logf("region_failover: region %q names an endpoint this device cannot parse (%q): %v — STAYING on the "+
			"endpoint already in force, which during an outage is the one that is down", ep.Region, ep.Endpoint, err)
		return err
	}
	var direct []string
	if a.upstreams != nil {
		direct = a.upstreams()
	}
	addrs := resolveRegionAddrs(host, port, direct)
	if len(addrs) == 0 {
		// A hostname we cannot resolve out of band yet: refuse to go live (dialing the name would deadlock under
		// DNS takeover). The loop keeps the prior endpoint (dials fail = deny) and retries next round.
		//
		// ★ SAID OUT LOUD, because the retry is invisible and the consequence is total: every dial keeps going
		// to the region being left. Naming the resolvers that were tried is the whole diagnosis -- out-of-band
		// resolution deliberately refuses the loopback proxy (that is the cycle it exists to break), so an empty
		// or unusable upstream list is how this device stays on a dead region while believing it may move.
		logf("region_failover: ★ CANNOT MOVE to region %q — its host %q did not resolve out of band "+
			"(upstream resolvers tried: %s). The endpoint already in force is KEPT, so every dial goes on "+
			"reaching the region this device is trying to leave. Retrying next round.",
			ep.Region, host, describeUpstreams(direct))
		return fmt.Errorf("could not resolve region %q endpoint host %q out of band", ep.Region, host)
	}
	prev := ""
	if cur := a.active.Load(); cur != nil {
		prev = cur.host
	}
	a.active.Store(&activeEndpoint{host: net.JoinHostPort(host, port), serverName: serverName, dialAddrs: addrs})
	if a.onEndpoint != nil {
		a.onEndpoint(addrs)
	}
	logf("region_failover: ★ now steering through region %q — dialling %s (verifying %q), was %q. "+
		"Every consumer's next dial follows this.",
		ep.Region, strings.Join(addrs, ","), serverName, emptyAs(prev, "(none)"))
	return nil
}

// bootstrapActiveEndpoint seeds transportConfig.active from the current single-endpoint config so every consumer
// has a valid live target BEFORE the region loop makes its first selection.
func bootstrapActiveEndpoint(tc transportConfig) *activeEndpoint {
	ae := &activeEndpoint{host: tc.host, serverName: tc.serverName}
	if tc.pins != nil {
		if p := tc.pins.Load(); p != nil {
			ae.dialAddrs = append([]string(nil), (*p)...)
		}
	}
	return ae
}

// parseRegionSeed parses a "region=URL;region=URL" seed (the MDM-shipped bootstrap list, used until the signed
// authoritative list is fetched). Empty -> nil.
func parseRegionSeed(raw string) ([]regionfailover.RegionEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []regionfailover.RegionEndpoint
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, endpoint, ok := strings.Cut(entry, "=")
		region = strings.ToLower(strings.TrimSpace(region))
		endpoint = strings.TrimSpace(endpoint)
		if !ok || region == "" || endpoint == "" {
			return nil, fmt.Errorf("region seed %q must be region=URL", entry)
		}
		if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "wss://") {
			return nil, fmt.Errorf("region seed %q URL must be https:// or wss://", entry)
		}
		out = append(out, regionfailover.RegionEndpoint{Region: region, Endpoint: endpoint})
	}
	return out, nil
}

// regionProbeTLSConfig builds the health probe's TLS configuration from the material that is IN FORCE, not the
// material this process started with.
//
// ★ THE PROBE WAS READING TWO STALE FIELDS (2026-08-20, found while auditing for the family the Edge side had
// just reported: a path that does not go through the one function). It used tc.rootCAs and tc.clientCert —
// the anchors loaded at start-up and the provisioned certificate — while every real dial uses the adopted
// anchors and the renewed identity. On this deployment both change at runtime: anchors when a distribution is
// adopted (which now happens seconds after the fleet publishes one), and the identity on every certificate
// renewal.
//
// The consequence is not a failed probe, it is a WRONG ANSWER about a region: a healthy region verified
// against withdrawn anchors reads as unreachable, and a device presenting a superseded certificate reads as
// not admitted. Failover decisions are then taken on both. The comment above says this probe must observe
// honestly; these two fields were the part that did not.
//
// Deliberately keeps its own name (the region's) rather than the organization's announced one: a region that
// has no certificate for this organization serves the deployment's shared one, and that is the same reason
// activeServerName lets region failover outrank the announcement.
func regionProbeTLSConfig(tc transportConfig, serverName string) *tls.Config {
	// Roots only. trustSnapshot is the one accessor for live trust material, and its own comment explains why
	// anything reading both halves must take them from here; a probe needs no session cache at all.
	_, roots := tc.trustSnapshot()
	cfg := &tls.Config{ServerName: probeSNI(tc, serverName), RootCAs: roots, MinVersion: tls.VersionTLS12}
	if cert := tc.currentClientCert(); cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

// probeSNI is the name the health probe puts in its ClientHello.
//
// ★★★ IT MUST BE THE NAME THE REAL DIAL SENDS (2026-08-30). It was the region endpoint's own hostname while
// every real connection sent this organization's announced name, and the SNI is what the Edge selects a
// CERTIFICATE with. So the probe asked for the deployment's shared certificate, verified it against the
// anchors this ORGANIZATION adopted, and -- correctly -- failed: an x509 failure, which is not an admission
// rejection, so the region was classified UNREACHABLE. Both regions. Roughly seventy seconds after arming,
// once the organization's own trust distribution had been adopted, every region went unreachable at once and
// the engine declared FAIL-CLOSED while the tunnel beside it carried traffic without dropping a request.
//
// A health probe that selects a different certificate from the connection whose health it reports is not
// measuring that connection. Anything else it gets right is a coincidence.
//
// The region's own hostname stays as the fallback for a deployment that announces no name -- the same rule,
// and the same order, as activeServerName().
func probeSNI(tc transportConfig, regionHost string) string {
	if n := tc.activeServerName(); strings.TrimSpace(n) != "" {
		return n
	}
	return regionHost
}

// probeLogf reports a probe verdict, at most once per distinct message per minute.
//
// ★ RATE-LIMITED, NOT SILENT. The probe runs every few seconds against every seeded region, so logging every
// verdict would bury the log — which is how the useful line gets removed later and the next outage is
// diagnosed blind again. Deduplicating on the message keeps a persistent fault visible once a minute and a
// flapping one visible as it flaps.
var probeLogSeen sync.Map // message -> time.Time of last emission

func probeLogf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	now := time.Now()
	if v, ok := probeLogSeen.Load(msg); ok {
		if last, fine := v.(time.Time); fine && now.Sub(last) < time.Minute {
			return
		}
	}
	probeLogSeen.Store(msg, now)
	log.Print(msg)
}
