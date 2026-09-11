//go:build windows

// capture_wfp_inbound_live_test.go — single-machine integration tests for the  inbound data path.
// Gated behind DSSE_WFP_LIVE=1 (requires the driver loaded + admin); skipped in normal `go test`. They drive
// real inbound TCP connections to this host's LAN IP (a genuine ALE_AUTH_RECV_ACCEPT with a non-loopback
// remote) and assert the kernel callout's behaviour:
//   - TestInboundLiveObserve: observe mode (Enforce=0) records the flow in the ring and PERMITs it.
//   - TestInboundLiveEnforce: enforce mode (Enforce=1) PERMITs an allowed source/port and BLOCKs the rest
//     (default-deny). Brief and self-clearing. A second host (Mac) as initiator is the more faithful test,
//     but the kernel permit/block/record paths are fully exercised here on one box.
package main

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func nonLoopbackV4(t *testing.T) net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs: %v", err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 != nil && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() {
			return v4
		}
	}
	t.Skip("no usable non-loopback IPv4 interface")
	return nil
}

func TestInboundLiveObserve(t *testing.T) {
	if os.Getenv("DSSE_WFP_LIVE") != "1" {
		t.Skip("set DSSE_WFP_LIVE=1 to run (needs driver loaded + admin)")
	}
	lanIP := nonLoopbackV4(t)

	// Observe-mode policy: record would-be-governed inbound, always PERMIT. No rules needed.
	var pol wfpInboundPolicy
	pol.Version = wfpInboundPolicyVer
	pol.DefaultDeny = 1
	pol.Enforce = 0
	if err := pushInboundPolicy(&pol); err != nil {
		t.Fatalf("pushInboundPolicy (driver loaded? admin?): %v", err)
	}
	t.Cleanup(func() { _ = removeInboundPolicy() })

	// drain any pre-existing records so we observe only our own connection.
	_, _ = drainInboundObservations()

	// Listen on the LAN IP (NOT loopback) and connect to it from this host -> a genuine inbound accept that
	// traverses ALE_AUTH_RECV_ACCEPT with a non-loopback remote address.
	ln, err := net.Listen("tcp", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", lanIP, err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var localPort uint16
	fmt.Sscanf(portStr, "%d", &localPort)

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("inbound connection was not accepted (observe mode must PERMIT)")
	}

	// Give the classify a moment, then drain and look for our local port.
	time.Sleep(300 * time.Millisecond)
	obs, err := drainInboundObservations()
	if err != nil {
		t.Fatalf("drainInboundObservations: %v", err)
	}
	t.Logf("drained %d inbound observation(s); looking for LocalPort=%d", len(obs), localPort)
	found := false
	for _, o := range obs {
		t.Logf("  obs: family=%d pid=%d remote=%v rport=%d lport=%d proto=%d action=%d",
			o.Family, o.ProcessId, net.IP(o.RemoteAddr[:4]), o.RemotePort, o.LocalPort, o.Protocol, o.Action)
		if o.LocalPort == localPort {
			found = true
		}
	}
	if !found {
		t.Errorf("did not observe an inbound flow with LocalPort=%d (callout may not fire for self-connect; "+
			"verify with a second host as initiator)", localPort)
	}
}

// TestInboundLiveEnforce verifies the S3b default-deny BLOCK path on a single machine: an enforce policy that
// allows the source IP only to one local port must PERMIT inbound to that port and BLOCK inbound to any other.
// Enforce default-denies unmatched inbound, so this is brief and the policy is cleared immediately after.
func TestInboundLiveEnforce(t *testing.T) {
	if os.Getenv("DSSE_WFP_LIVE") != "1" {
		t.Skip("set DSSE_WFP_LIVE=1 to run (needs driver loaded + admin)")
	}
	lanIP := nonLoopbackV4(t)

	// Two listeners on the LAN IP: one allowed, one not.
	lnAllow, err := net.Listen("tcp", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		t.Fatalf("listen allow: %v", err)
	}
	defer lnAllow.Close()
	lnDeny, err := net.Listen("tcp", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		t.Fatalf("listen deny: %v", err)
	}
	defer lnDeny.Close()
	go func() {
		for {
			c, e := lnAllow.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	go func() {
		for {
			c, e := lnDeny.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()

	_, allowPortStr, _ := net.SplitHostPort(lnAllow.Addr().String())
	var allowPort uint16
	fmt.Sscanf(allowPortStr, "%d", &allowPort)

	// Build an enforce policy allowing lanIP -> allowPort only. (Mirrors what an export with a Legacy
	// Exception for that source/port would produce; here we construct it directly to isolate the kernel path.)
	exp := &serverInitiatedExport{
		DefaultAction: "deny",
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "live", SourceServer: lanIP.String(), DeviceGroup: "test",
				ServiceFamily: "smb", Port: int(allowPort), Action: "allow"},
		},
	}
	pol, berrs := buildWFPInboundPolicy(exp, "test", net.LookupIP, true)
	if len(berrs) != 0 {
		t.Fatalf("build errors: %v", berrs)
	}
	if err := pushInboundPolicy(&pol); err != nil {
		t.Fatalf("pushInboundPolicy: %v", err)
	}
	defer func() { _ = removeInboundPolicy() }()

	// Allowed port: connect must succeed.
	if c, e := net.DialTimeout("tcp", lnAllow.Addr().String(), 2*time.Second); e != nil {
		t.Errorf("allowed inbound to :%d was refused: %v", allowPort, e)
	} else {
		c.Close()
	}
	// Denied port: connect must be blocked (refused/reset/timeout) by default-deny.
	if c, e := net.DialTimeout("tcp", lnDeny.Addr().String(), 2*time.Second); e == nil {
		c.Close()
		t.Errorf("inbound to non-allowed port %s succeeded, want BLOCK (default-deny)", lnDeny.Addr())
	} else {
		t.Logf("non-allowed inbound correctly blocked: %v", e)
	}
}
