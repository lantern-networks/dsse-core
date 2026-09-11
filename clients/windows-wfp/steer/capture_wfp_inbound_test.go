//go:build windows

package main

import (
	"errors"
	"net"
	"testing"
	"unsafe"
)

// TestInboundStructLockstep guards the byte-for-byte contract with dsse_wfp.h. If these sizes drift,
// the IOCTL marshalling silently corrupts and the driver rejects/ misreads the policy.
func TestInboundStructLockstep(t *testing.T) {
	if got := unsafe.Sizeof(wfpInboundRule{}); got != 28 {
		t.Errorf("wfpInboundRule size = %d, want 28 (DSSE_INBOUND_RULE)", got)
	}
	if got := unsafe.Sizeof(wfpInboundPolicy{}); got != uintptr(16+wfpMaxInboundRules*28) {
		t.Errorf("wfpInboundPolicy size = %d, want %d", got, 16+wfpMaxInboundRules*28)
	}
	if got := unsafe.Sizeof(wfpInboundObservation{}); got != 32 {
		t.Errorf("wfpInboundObservation size = %d, want 32 (DSSE_INBOUND_OBSERVATION)", got)
	}
}

func TestBuildWFPInboundPolicy_IPLiteralAllow(t *testing.T) {
	exp := &serverInitiatedExport{
		SchemaVersion: "server_initiated_export.v1",
		DefaultAction: "deny",
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "e1", SourceServer: "203.0.113.10", DeviceGroup: "workstations",
				ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
	p, errs := buildWFPInboundPolicy(exp, "workstations", nil, true)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if p.Enforce != 1 || p.DefaultDeny != 1 {
		t.Fatalf("Enforce=%d DefaultDeny=%d, want 1/1", p.Enforce, p.DefaultDeny)
	}
	if p.NumRules != 1 {
		t.Fatalf("NumRules=%d, want 1", p.NumRules)
	}
	// the allowed source can reach smb:445, but not rdp:3389 and not from another IP.
	if !inboundPolicyAllows(&p, net.ParseIP("203.0.113.10"), 445, ipProtoTCP) {
		t.Error("expected 203.0.113.10 -> :445 allowed")
	}
	if inboundPolicyAllows(&p, net.ParseIP("203.0.113.10"), 3389, ipProtoTCP) {
		t.Error("expected :3389 denied (no rule)")
	}
	if inboundPolicyAllows(&p, net.ParseIP("10.0.0.9"), 445, ipProtoTCP) {
		t.Error("expected other source denied")
	}
}

// Review #25: default_action=allow is OPERATOR CONFIG — DSSE stops managing inbound, so the WFP kernel
// policy must NOT impose a default-deny (mirroring the netsh backend). The old code hardcoded DefaultDeny=1
// regardless, silently overriding the operator's allow-by-default choice on the WFP path.
func TestBuildWFPInboundPolicy_DefaultActionAllowStopsManaging(t *testing.T) {
	exp := &serverInitiatedExport{
		SchemaVersion: "server_initiated_export.v1",
		DefaultAction: "allow",
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "e1", SourceServer: "203.0.113.10", DeviceGroup: "workstations",
				ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
	p, errs := buildWFPInboundPolicy(exp, "workstations", nil, true)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if p.DefaultDeny != 0 {
		t.Fatalf("DefaultDeny=%d, want 0 (allow-by-default = not managing)", p.DefaultDeny)
	}
	if p.NumRules != 0 {
		t.Fatalf("NumRules=%d, want 0 (no rules when not managing)", p.NumRules)
	}
}

func TestBuildWFPInboundPolicy_GroupFilterAndDenyDropped(t *testing.T) {
	exp := &serverInitiatedExport{
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "mine", SourceServer: "10.1.1.1", DeviceGroup: "workstations", ServiceFamily: "smb", Port: 445, Action: "allow"},
			{ExceptionID: "other", SourceServer: "10.2.2.2", DeviceGroup: "servers", ServiceFamily: "smb", Port: 445, Action: "allow"},
			{ExceptionID: "deny", SourceServer: "10.3.3.3", DeviceGroup: "workstations", ServiceFamily: "rdp", Port: 3389, Action: "deny"},
			{ExceptionID: "wild", SourceServer: "10.4.4.4", DeviceGroup: "*", ServiceFamily: "winrm", Port: 5985, Action: "allow"},
		},
	}
	p, errs := buildWFPInboundPolicy(exp, "workstations", nil, true)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// keep: "mine" (group match) + "wild" (wildcard group). drop: "other" (wrong group), "deny" (deny action).
	if p.NumRules != 2 {
		t.Fatalf("NumRules=%d, want 2", p.NumRules)
	}
	if !inboundPolicyAllows(&p, net.ParseIP("10.1.1.1"), 445, ipProtoTCP) {
		t.Error("group-matched allow missing")
	}
	if !inboundPolicyAllows(&p, net.ParseIP("10.4.4.4"), 5985, ipProtoTCP) {
		t.Error("wildcard-group allow missing")
	}
	if inboundPolicyAllows(&p, net.ParseIP("10.2.2.2"), 445, ipProtoTCP) {
		t.Error("wrong-group rule must not be present")
	}
	if inboundPolicyAllows(&p, net.ParseIP("10.3.3.3"), 3389, ipProtoTCP) {
		t.Error("deny-action rule must be dropped (default-deny covers it)")
	}
}

func TestBuildWFPInboundPolicy_HostnameResolution(t *testing.T) {
	exp := &serverInitiatedExport{
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "h", SourceServer: "patchsrv", DeviceGroup: "workstations", ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
	resolve := func(host string) ([]net.IP, error) {
		if host == "patchsrv" {
			return []net.IP{net.ParseIP("172.16.5.5"), net.ParseIP("172.16.5.6")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	p, errs := buildWFPInboundPolicy(exp, "workstations", resolve, true)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if p.NumRules != 2 { // one rule per resolved IP
		t.Fatalf("NumRules=%d, want 2 (one per resolved IP)", p.NumRules)
	}
	if !inboundPolicyAllows(&p, net.ParseIP("172.16.5.5"), 445, ipProtoTCP) ||
		!inboundPolicyAllows(&p, net.ParseIP("172.16.5.6"), 445, ipProtoTCP) {
		t.Error("both resolved IPs should be allowed")
	}
}

func TestBuildWFPInboundPolicy_UnresolvableIsOmitted(t *testing.T) {
	exp := &serverInitiatedExport{
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "bad", SourceServer: "ghost", DeviceGroup: "workstations", ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
	// nil resolver: a hostname cannot be resolved -> rule omitted (falls under default-deny), error reported.
	p, errs := buildWFPInboundPolicy(exp, "workstations", nil, true)
	if p.NumRules != 0 {
		t.Fatalf("NumRules=%d, want 0 (unresolvable omitted)", p.NumRules)
	}
	if len(errs) != 1 {
		t.Fatalf("errs=%d, want 1", len(errs))
	}
}

func TestBuildWFPInboundPolicy_ObserveMode(t *testing.T) {
	exp := &serverInitiatedExport{
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "e", SourceServer: "10.0.0.1", DeviceGroup: "workstations", ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
	p, _ := buildWFPInboundPolicy(exp, "workstations", nil, false) // observe
	if p.Enforce != 0 {
		t.Errorf("Enforce=%d, want 0 (observe mode)", p.Enforce)
	}
	if p.DefaultDeny != 1 {
		t.Errorf("DefaultDeny=%d, want 1", p.DefaultDeny)
	}
}

func TestInboundWildcardPort(t *testing.T) {
	exp := &serverInitiatedExport{
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "any", SourceServer: "10.0.0.1", DeviceGroup: "workstations", ServiceFamily: "smb", Port: 0, Action: "allow"},
		},
	}
	p, _ := buildWFPInboundPolicy(exp, "workstations", nil, true)
	// port 0 in export => LocalPort wildcard => any local port from that source matches.
	if !inboundPolicyAllows(&p, net.ParseIP("10.0.0.1"), 445, ipProtoTCP) {
		t.Error("wildcard port should match 445")
	}
	if !inboundPolicyAllows(&p, net.ParseIP("10.0.0.1"), 3389, ipProtoTCP) {
		t.Error("wildcard port should match 3389")
	}
}
