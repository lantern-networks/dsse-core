package main

import (
	"net/netip"
	"testing"
)

func ptAP(s string) netip.AddrPort { a, _ := netip.ParseAddrPort(s); return a }

// ★ The defect: the Console's addresses never reached the capture, so a steered administrator got 502 from
// the deployment they were steering. The passthrough set has to be part of what the backend enforces.
func TestPassthroughAddressesReachTheEnforcedSet(t *testing.T) {
	d := newLiveDests([]netip.AddrPort{ptAP("10.0.0.1:22")})
	d.setPassthrough([]netip.AddrPort{ptAP("57.181.7.32:443"), ptAP("57.181.7.32:80")})
	got := d.effective()
	if len(got) != 3 {
		t.Fatalf("the passthrough addresses did not reach the enforced set: %v", got)
	}
}

// ★ Every family the name answers with is kept. An address-shaped exception stops matching the moment a
// family is added — thirty minutes of a two-region outage were spent on exactly that.
func TestBothFamiliesAreKept(t *testing.T) {
	d := newLiveDests(nil)
	d.setPassthrough([]netip.AddrPort{ptAP("57.181.7.32:443"), ptAP("[2606:4700::1]:443")})
	got := d.effective()
	if len(got) != 2 {
		t.Fatalf("a family was dropped: %v", got)
	}
}

// A re-resolution that finds the same answers, in a different order, is not a change: it must not re-push
// the kernel policy every five minutes.
func TestTheSameAnswersInAnotherOrderAreNotAChange(t *testing.T) {
	d := newLiveDests(nil)
	first := []netip.AddrPort{ptAP("1.2.3.4:443"), ptAP("5.6.7.8:443")}
	if !d.setPassthrough(first) {
		t.Fatal("the first application should count as a change")
	}
	if d.setPassthrough([]netip.AddrPort{ptAP("5.6.7.8:443"), ptAP("1.2.3.4:443")}) {
		t.Fatal("a reordered identical set was reported as a change")
	}
	if !d.setPassthrough([]netip.AddrPort{ptAP("1.2.3.4:443")}) {
		t.Fatal("a genuinely smaller set was not reported as a change")
	}
}

// The Edge slot and the passthrough set are independent: filling one must not disturb the other, because
// they are corrected by different loops at different times.
func TestTheEdgeSlotAndPassthroughDoNotDisturbEachOther(t *testing.T) {
	d := newLiveDests(nil)
	d.setPassthrough([]netip.AddrPort{ptAP("57.181.7.32:443")})
	d.setEdge(ptAP("16.208.65.143:443"))
	got := d.effective()
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	d.setPassthrough([]netip.AddrPort{ptAP("57.181.7.32:443"), ptAP("57.181.7.32:80")})
	if len(d.effective()) != 3 {
		t.Fatalf("the Edge slot was lost when the passthrough set changed: %v", d.effective())
	}
}
