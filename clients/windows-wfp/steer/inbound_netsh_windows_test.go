//go:build windows

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func testExport() *serverInitiatedExport {
	return &serverInitiatedExport{
		SchemaVersion: "server_initiated_export.v1",
		DefaultAction: "deny",
		Rules: []serverInitiatedExportRule{
			{ExceptionID: "ex-allow", SourceServer: "10.10.0.10", DeviceGroup: "lab", ServiceFamily: "smb", Port: 445, Action: "allow"},
			{ExceptionID: "ex-deny", SourceServer: "10.10.0.66", DeviceGroup: "lab", ServiceFamily: "rdp", Port: 3389, Action: "deny"},
			{ExceptionID: "ex-observe", SourceServer: "10.10.0.10", DeviceGroup: "lab", ServiceFamily: "ssh", Port: 22, Action: "log"},
			{ExceptionID: "ex-othergroup", SourceServer: "10.10.0.10", DeviceGroup: "hq", ServiceFamily: "smb", Port: 445, Action: "allow"},
			{ExceptionID: "ex-anygroup", SourceServer: "10.10.0.11", DeviceGroup: "*", ServiceFamily: "winrm", Port: 5985, Action: "allow"},
			{ExceptionID: "ex-hostname", SourceServer: "dc.lab.example", DeviceGroup: "lab", ServiceFamily: "smb", Port: 445, Action: "allow"},
		},
	}
}

func TestBuildFirewallRules(t *testing.T) {
	resolve := func(host string) ([]net.IP, error) {
		if host == "dc.lab.example" {
			return []net.IP{net.ParseIP("10.10.0.12"), net.ParseIP("fd00::12")}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	rules, errs := buildFirewallRules(testExport(), "lab", resolve)
	if len(errs) != 0 {
		t.Fatalf("unexpected build errors: %v", errs)
	}
	// ex-allow, ex-deny, ex-anygroup (wildcard group), ex-hostname. NOT ex-observe (log) / ex-othergroup (hq).
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4: %+v", len(rules), rules)
	}
	byName := map[string]fwRule{}
	for _, r := range rules {
		byName[r.name] = r
	}
	if r := byName["DSSE-inbound-ex-allow"]; r.action != "Allow" || r.protocol != "TCP" || r.port != 445 || len(r.remoteAddrs) != 1 || r.remoteAddrs[0] != "10.10.0.10" {
		t.Fatalf("ex-allow mapped wrong: %+v", r)
	}
	if r := byName["DSSE-inbound-ex-deny"]; r.action != "Block" || r.port != 3389 {
		t.Fatalf("ex-deny mapped wrong: %+v", r)
	}
	if _, ok := byName["DSSE-inbound-ex-anygroup"]; !ok {
		t.Fatalf("wildcard device_group rule missing: %+v", rules)
	}
	if r := byName["DSSE-inbound-ex-hostname"]; len(r.remoteAddrs) != 2 {
		t.Fatalf("hostname rule should expand to 2 resolved IPs: %+v", r)
	}
}

func TestBuildFirewallRulesResolveFailureFailsClosed(t *testing.T) {
	exp := &serverInitiatedExport{Rules: []serverInitiatedExportRule{
		{ExceptionID: "ex-bad", SourceServer: "nope.invalid", DeviceGroup: "lab", ServiceFamily: "smb", Port: 445, Action: "allow"},
	}}
	rules, errs := buildFirewallRules(exp, "lab", func(string) ([]net.IP, error) { return nil, fmt.Errorf("NXDOMAIN") })
	if len(rules) != 0 {
		t.Fatalf("unresolvable source must be omitted (default-deny), got %+v", rules)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 build error, got %v", errs)
	}
}

func TestBuildFirewallRulesAllowByDefaultWithdrawsAll(t *testing.T) {
	exp := testExport()
	exp.DefaultAction = "allow" // Console "allow by default" (server_initiated_enabled=false)
	rules, errs := buildFirewallRules(exp, "lab", nil)
	if len(rules) != 0 || len(errs) != 0 {
		t.Fatalf("allow-by-default must withdraw all DSSE rules, got %v / %v", rules, errs)
	}
}

func TestBuildFirewallRulesNilExport(t *testing.T) {
	rules, errs := buildFirewallRules(nil, "lab", nil)
	if len(rules) != 0 || len(errs) != 0 {
		t.Fatalf("nil export must yield empty desired state, got %v / %v", rules, errs)
	}
}

func TestFirewallReconcileScript(t *testing.T) {
	rules := []fwRule{
		{name: "DSSE-inbound-a", action: "Allow", protocol: "TCP", port: 445, remoteAddrs: []string{"10.10.0.10"}},
		{name: "DSSE-inbound-b", action: "Block", protocol: "TCP", port: 3389, remoteAddrs: []string{"10.10.0.66"}},
	}
	s := firewallReconcileScript(rules)
	for _, want := range []string{
		"try { Get-NetFirewallRule -Group 'DSSE Server-Initiated' -ErrorAction Stop | Remove-NetFirewallRule } catch {}",
		"New-NetFirewallRule -DisplayName 'DSSE-inbound-a' -Group 'DSSE Server-Initiated' -Direction Inbound -Action Allow -Profile Any -Enabled True -Protocol TCP -LocalPort 445 -RemoteAddress @('10.10.0.10')",
		"-Action Block",
		"ADDFAIL DSSE-inbound-b",
		"Write-Output 'DSSE-RECONCILE-COMPLETE'",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q:\n%s", want, s)
		}
	}
}

func TestFirewallScriptInjectionStripped(t *testing.T) {
	exp := &serverInitiatedExport{Rules: []serverInitiatedExportRule{
		{ExceptionID: "x'; Remove-Item C:\\ -Recurse #", SourceServer: "10.0.0.1", DeviceGroup: "", ServiceFamily: "smb", Port: 445, Action: "allow"},
	}}
	rules, _ := buildFirewallRules(exp, "lab", nil)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %+v", rules)
	}
	// the quote/semicolon/$ must be stripped so the payload cannot escape the single-quoted literal; the
	// remaining benign text stays safely inside the quotes.
	if got := rules[0].name; strings.ContainsAny(got, "';$`") {
		t.Fatalf("injection characters survived into the rule name: %q", got)
	}
	if s := firewallReconcileScript(rules); strings.Contains(s, "x';") {
		t.Fatalf("payload escaped the quoted literal:\n%s", s)
	}
}

func TestFwFingerprintChangesWithRules(t *testing.T) {
	a := []fwRule{{name: "n", action: "Allow", protocol: "TCP", port: 445, remoteAddrs: []string{"10.0.0.1"}}}
	b := []fwRule{{name: "n", action: "Allow", protocol: "TCP", port: 446, remoteAddrs: []string{"10.0.0.1"}}}
	if fwFingerprint(a) == fwFingerprint(b) {
		t.Fatal("fingerprint must change when a rule changes")
	}
	if fwFingerprint(nil) != "" {
		t.Fatal("empty rule set must fingerprint to empty")
	}
}
