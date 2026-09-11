package main

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// egress_address_family.go — what this Edge can actually reach the internet BY, measured rather than assumed.
//
// ★★★ NOBODY WAS MEASURING IT, AND AN AGENT WAS STEERING INTO WHAT DID NOT EXIST (2026-08-25, reported from
// win-dev-1 with the Edge's own logs as evidence).
//
// The agent captures ALL outbound TCP, IPv6 included — the right default, and what it is told to do. The
// generated deployment's container network has no IPv6 at all: `ip -6 addr` on the Edge shows only ::1, and
// the compose file has no enable_ipv6. So every v6 flow arrived, could not be egressed, and was closed with
// zero bytes. Over seventeen minutes on one endpoint:
//
//	IPv4   572 flows carried bytes, 0 empty
//	IPv6   342 carried, 185 EMPTY
//
// It survives today only because the application falls back to IPv4 (Happy Eyeballs) and because fail-open is
// on — a posture whose own flag says STABILIZATION ONLY. Under the posture this deployment is meant to ship
// with, a v6-only destination is simply unreachable, and every v6 attempt is a wasted round trip.
//
// ★ THE FIRST THING TO FIX IS NOT THE NETWORK, IT IS THE SILENCE. Whether a deployment can egress v6 depends
// on the host it runs on, which is exactly why the ANSWER has to travel rather than be assumed by either
// side. An Edge that cannot carry a family should be able to say so, so that what steers into it can be
// decided from a measurement instead of from a default.
//
// ★ IT IS A REACHABILITY TEST, NOT AN INTERFACE LIST. An interface can hold a global v6 address and still
// have no route off the host, and the failure looks identical from the agent. So this dials.
var egressFamilies atomic.Pointer[egressFamilyReport]

type egressFamilyReport struct {
	IPv4       bool      `json:"ipv4"`
	IPv6       bool      `json:"ipv6"`
	MeasuredAt time.Time `json:"measured_at"`
	// Note carries the consequence in the words somebody reading a health answer needs, rather than leaving
	// two booleans to be interpreted.
	Note string `json:"note,omitempty"`
}

// measureEgressFamilies dials a well-known address in each family and records which ones a connection can be
// opened in. Nothing is sent; the socket reaching ESTABLISHED is the whole question.
func measureEgressFamilies(probeV4, probeV6 string, timeout time.Duration) egressFamilyReport {
	dial := func(network, addr string) bool {
		if addr == "" {
			return false
		}
		c, err := net.DialTimeout(network, addr, timeout)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	r := egressFamilyReport{
		IPv4:       dial("tcp4", probeV4),
		IPv6:       dial("tcp6", probeV6),
		MeasuredAt: time.Now().UTC(),
	}
	switch {
	case r.IPv4 && r.IPv6:
		r.Note = "this node can egress in both families"
	case r.IPv4:
		r.Note = "this node has NO IPv6 egress: a device that steers IPv6 here has its flow closed with no " +
			"bytes, and a destination that is IPv6-only cannot be reached through it"
	case r.IPv6:
		r.Note = "this node has NO IPv4 egress"
	default:
		r.Note = "this node could not open an outbound connection in either family — it may have no egress " +
			"at all, or the probe addresses may be blocked"
	}
	return r
}

// startEgressFamilyMeasurement measures at start-up and then hourly — hourly because this is a property of the
// host's networking, which changes when somebody changes it and not otherwise, and a measurement nobody
// repeats becomes a claim about the day the process started.
//
// ★★★ AND A FAILURE IS RE-MEASURED SOON, BECAUSE ONE FAILED DIAL TOOK A WHOLE ADDRESS FAMILY AWAY FROM A
// FLEET (2026-09-02, measured from a Windows box that could not open ANY IPv4 destination while IPv6 worked
// on the same tunnel at the same moment).
//
// This answer is not advice. It is signed into the posture as CaptureAddressFamilies, and a Windows agent
// honours it by closing every flow of a family the deployment says it cannot carry — deliberately, so the
// application falls back instead of being steered into a hole. So a single timed-out probe here means:
//
//	steer_family_not_carried dst=1.1.1.1:443 — this deployment declared it cannot egress that address family
//
// on every Windows device of the fleet, for up to an hour, while the node in fact egresses that family
// perfectly well. macOS does not honour the field, so the same false posture is invisible on one platform and
// total on the other — which is why it read as "that box is broken" for an hour.
//
// ★★ A NEGATIVE IS THE EXPENSIVE ANSWER, so it has to be earned: re-measured quickly, and only believed after
// it repeats. A positive costs nothing to be slow about.
const (
	// egressFamilyRetryWhileNegative is how soon a node re-measures after saying it cannot carry a family.
	egressFamilyRetryWhileNegative = 60 * time.Second
	// egressFamilyNegativeStrikes is how many consecutive failures a family needs before this node PUBLISHES
	// that it cannot carry it. One is a probe that timed out; three in a row is the host's networking.
	egressFamilyNegativeStrikes = 3
)

func startEgressFamilyMeasurement(probeV4, probeV6 string) {
	if probeV4 == "" && probeV6 == "" {
		return
	}
	go func() {
		v4Strikes, v6Strikes := 0, 0
		for {
			r := measureEgressFamilies(probeV4, probeV6, 4*time.Second)
			if r.IPv4 {
				v4Strikes = 0
			} else {
				v4Strikes++
			}
			if r.IPv6 {
				v6Strikes = 0
			} else {
				v6Strikes++
			}
			// A family that has not failed often enough keeps its last published answer, which on a fleet that
			// was carrying it means it goes on being carried.
			published := r
			if !r.IPv4 && v4Strikes < egressFamilyNegativeStrikes {
				published.IPv4 = true
			}
			if !r.IPv6 && v6Strikes < egressFamilyNegativeStrikes {
				published.IPv6 = true
			}
			if published != r {
				logWarnf("egress_address_family: probe says ipv4=%v ipv6=%v — NOT published yet (%d/%d, %d/%d "+
					"consecutive failures). A single failed probe would close this family on every device that "+
					"honours the posture", r.IPv4, r.IPv6, v4Strikes, egressFamilyNegativeStrikes, v6Strikes,
					egressFamilyNegativeStrikes)
			}
			publishEgressFamilies(published)
			if v4Strikes > 0 || v6Strikes > 0 {
				time.Sleep(egressFamilyRetryWhileNegative)
				continue
			}
			time.Sleep(time.Hour)
		}
	}()
}

// measureAndPublishEgressFamilies is one measurement and everything that must learn from it. It is a named
// function rather than a closure so a test can run it SYNCHRONOUSLY: the thing worth testing here is that the
// dialer takes this answer, and a test that starts a goroutine and then waits proves that only on the days
// the machine is fast enough.
func measureAndPublishEgressFamilies(probeV4, probeV6 string) {
	publishEgressFamilies(measureEgressFamilies(probeV4, probeV6, 4*time.Second))
}

// publishEgressFamilies is everything that must learn from a measurement, separated from taking it so the
// caller can decide whether an answer has been earned. See startEgressFamilyMeasurement.
func publishEgressFamilies(r egressFamilyReport) {
	egressFamilies.Store(&r)
	// ★★★ AND THE FLOW DECISION TAKES THIS ANSWER, NOT ONE OF ITS OWN (2026-08-30). Until today the dialer
	// decided the same question by listing interface addresses, called a NAT66 container v6-less because its
	// only v6 address is a ULA, and re-fetched every IPv6 destination by name over IPv4 — while this line
	// logged ipv6=true. Two answers to one question, and the wrong one was the one that moved packets.
	edgeplane.SetMeasuredIPv6Egress(r.IPv6)
	if !r.IPv6 {
		logWarnf("egress_address_family ipv4=%v ipv6=%v — %s", r.IPv4, r.IPv6, r.Note)
	} else {
		logInfof("egress_address_family ipv4=%v ipv6=%v", r.IPv4, r.IPv6)
	}
}

// egressFamiliesForReport is what this node says about it, or nil when it has not measured.
func egressFamiliesForReport() any {
	if r := egressFamilies.Load(); r != nil {
		return r
	}
	return nil
}
