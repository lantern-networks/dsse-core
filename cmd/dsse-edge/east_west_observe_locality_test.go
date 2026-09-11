package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func lateralReq(dest string) model.DecisionRequest {
	return model.DecisionRequest{
		ServiceFamily: "ssh", Destination: dest, FQDN: dest, DestinationPort: 22, Protocol: "tcp",
	}
}

func isLateral(t *testing.T, dest string) bool {
	t.Helper()
	req := resolveDestinationForLocality(context.Background(), lateralReq(dest), decision.InternalNetworks{}, time.Now())
	return decision.IsEastWestFlow(req, decision.InternalNetworks{})
}

func withResolver(t *testing.T, f func(context.Context, string) ([]net.IP, error)) {
	t.Helper()
	prev := observeResolver
	observeResolver = f
	observeLocality = newObserveLocalityCache()
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
}

// ★★ THE FLOW THE OPERATOR SAW (2026-08-14). `ssh github.com` sat in the lateral inventory — the queue whose
// next action is "adopt this into a lateral rule" — because DestinationIP is never populated on the steer path,
// so the name classified as Unknown, and east-west admits everything that is not Public.
func TestAPublicNameIsNotLateralOnceResolved(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.4")}, nil
	})
	if isLateral(t, "github.com") {
		t.Fatal("ssh to a public host is still governed on the lateral plane — it is denied for want of a rule, " +
			"and it appears in the adoption queue whose next action would author a lateral rule for the internet")
	}
}

func TestAPrivateNameIsStillLateral(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.20.0.20")}, nil
	})
	if !isLateral(t, "fileserver.corp") {
		t.Fatal("a name that resolves inside the private space was dropped from the lateral inventory")
	}
}

// ★ NOT KNOWING IS NOT EVIDENCE OF BEING PUBLIC. A resolution failure must keep the flow in the inventory —
// the failure that costs something is dropping a private destination from lateral governance, which is the
// same reason enforcement admits Unknown.
func TestAnUnresolvableNameIsPreserved(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("no such host")
	})
	if !isLateral(t, "host.invalid") {
		t.Fatal("a name that could not be resolved was dropped from the lateral plane")
	}
	// And the failure is NOT cached: a transient DNS problem must not pin the answer for the TTL.
	calls := 0
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		calls++
		return nil, errors.New("no such host")
	})
	isLateral(t, "host.invalid")
	isLateral(t, "host.invalid")
	if calls != 2 {
		t.Fatalf("a failed lookup was cached (%d call(s) for 2 flows) — a transient DNS failure would pin the "+
			"answer for %s", calls, observeLocalityTTL)
	}
}

// ★★ A SPLIT-HORIZON NAME STAYS. One public A record is not proof the flow was not lateral, and dropping it
// would hide exactly the destination an operator needs to govern.
func TestAMixedResolutionIsStillLateral(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.4"), net.ParseIP("10.20.0.20")}, nil
	})
	if !isLateral(t, "split.example") {
		t.Fatal("a name resolving both publicly and privately was dropped from the lateral inventory")
	}
}

// The answer is cached, so a run of flows to one host costs one lookup on the flow-open path.
func TestTheResolvedAnswerIsReused(t *testing.T) {
	calls := 0
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("140.82.121.4")}, nil
	})
	for i := 0; i < 5; i++ {
		isLateral(t, "github.com")
	}
	now := time.Now()
	if calls != 1 {
		t.Fatalf("%d lookups for 5 flows to one host — this runs on the flow-open path", calls)
	}
	// And it expires, so a destination that moves networks is reclassified.
	if _, ok := observeLocality.get("github.com", now.Add(observeLocalityTTL+time.Second)); ok {
		t.Fatal("the cached answer outlived its TTL")
	}
}

// An IP literal needs no resolution and must keep classifying exactly as before.
func TestIPLiteralsAreUnchanged(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		t.Fatal("an IP literal triggered a DNS lookup")
		return nil, nil
	})
	if isLateral(t, "18.178.117.232") {
		t.Fatal("a public IP literal is recorded as lateral")
	}
	if !isLateral(t, "10.20.0.10") {
		t.Fatal("a private IP literal was dropped from the inventory")
	}
}

// ★★ ENFORCEMENT AND THE INVENTORY ANSWER FROM THE SAME PREDICATE (2026-08-14). An earlier version resolved
// only for the inventory and left enforcement admitting the unresolved name, which fixed the screen and left
// `ssh git@github.com` denied on the device. Two answers to one question is the shape this codebase keeps
// paying for; the resolution belongs in the request, once, ahead of both.
func TestTheUnresolvedRequestStillClassifiesAsUnknown(t *testing.T) {
	// Nothing resolved: DestinationIP untouched, no resolved address, so the classifier answers Unknown and
	// east-west admits it — the preserving behaviour, unchanged.
	if !decision.IsEastWestFlow(lateralReq("github.com"), decision.InternalNetworks{}) {
		t.Fatal("a request carrying no address at all stopped being admitted — that would drop private " +
			"destinations this Edge cannot classify out of lateral governance")
	}
}

// ★ AND DestinationIP IS NEVER TOUCHED. Other decisions read it — destinationAddressScope treats an FQDN as
// public and a private literal as Default-Deny — so filling it with a resolved address would move every
// internal host reached by name from allow+intercept to default-deny. A different decision, in the deny
// direction, and not the one being made here.
func TestResolutionDoesNotRewriteWhatTheClientAskedFor(t *testing.T) {
	withResolver(t, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.20.0.20")}, nil
	})
	got := resolveDestinationForLocality(context.Background(), lateralReq("fileserver.corp"), decision.InternalNetworks{}, time.Now())
	if got.DestinationIP != "" {
		t.Fatalf("DestinationIP was rewritten to %q — that changes decisions this fix is not about", got.DestinationIP)
	}
	if got.DestinationResolvedIP != "10.20.0.20" {
		t.Fatalf("DestinationResolvedIP = %q, want the resolved address", got.DestinationResolvedIP)
	}
}
