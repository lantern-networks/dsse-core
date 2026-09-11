//go:build windows

package main

// inbound_netsh_windows.go — server-initiated inbound enforcement via the STANDARD Windows Defender Firewall
// (real, visible inbound rules) instead of the custom WFP callout driver (capture_wfp_inbound.go / driver.c).
// See docs/server_initiated_windows_firewall_handoff.md.
//
// It reuses the existing fetch (loadInboundExport → server_initiated_export.v1), the group filter
// (groupMatches) and the service_family→protocol mapping (serviceFamilyProtocol); it only changes ENFORCEMENT
// from an IOCTL-to-driver to Windows Firewall rules. Windows already default-denies unsolicited inbound, so
// v1 manages only the exception rules and never touches the profile DefaultInboundAction (handoff
// recommendation: least surprise). Observe (log/log_alert) actions get no enforcing rule in v1.
//
// NOTE: this backend shells out to powershell.exe, so it must run from a normal elevated session — a session-0
// service cannot spawn child processes (0xC0000142; see quicblock_windows.go for the same constraint).

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// dsseFirewallGroup tags every rule we create so a poll can list + clear our own rules idempotently without
// touching anything else in the machine's firewall.
const dsseFirewallGroup = "DSSE Server-Initiated"

// fwReconcileEvery forces a full reconcile every N polls even when the export is unchanged, so manual rule
// deletion/tampering self-heals without delete/recreate flapping on every poll.
const fwReconcileEvery = 10

// hiddenPowerShell runs a PowerShell (NetSecurity module) command with no visible window — mirrors hiddenNetsh
// in quicblock_windows.go. Firewall changes require an ELEVATED process.
func hiddenPowerShell(script string) (*exec.Cmd, error) {
	// From the system directory, never %PATH% — see package winbin. This one runs an ELEVATED script that
	// rewrites the machine's inbound firewall rules; "whatever answers first on the search path" is not an
	// acceptable answer to which interpreter gets to do that.
	ps, err := winbin.PowerShell()
	if err != nil {
		return nil, err
	}
	c := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c, nil
}

// fwRule is one desired Windows Firewall inbound rule, derived from an export rule.
type fwRule struct {
	name        string   // DSSE-inbound-<exception_id>
	action      string   // Allow | Block
	protocol    string   // TCP | UDP | "" (any; port is then ignored — -LocalPort needs a protocol)
	port        int      // 0 = any
	remoteAddrs []string // resolved source IPs; empty = any source
}

// protoName maps the existing serviceFamilyProtocol() IP-protocol number to a Windows Firewall -Protocol name.
// Empty family (no protocol constraint) => "" = any protocol (match by source only).
func protoName(family string) string {
	if strings.TrimSpace(family) == "" {
		return ""
	}
	switch serviceFamilyProtocol(family) { // existing helper: smb/rdp/ssh/... => 6 (TCP); unknown => TCP
	case 17:
		return "UDP"
	default:
		return "TCP"
	}
}

// buildFirewallRules converts an S2 export into the desired firewall rule set (pure given a resolver;
// unit-tested). Same per-rule fail-closed semantics as buildWFPInboundPolicy: a rule whose source_server
// cannot be resolved is omitted, so it falls under Windows' default-deny inbound — never accidentally widened.
func buildFirewallRules(exp *serverInitiatedExport, deviceGroup string, resolve inboundResolver) ([]fwRule, []error) {
	var rules []fwRule
	var errs []error
	if exp == nil {
		return rules, errs
	}
	// "Allow by default" (Console: server_initiated_enabled=false → export default_action=allow): DSSE stops
	// managing inbound — desired state is NO rules (the group is withdrawn) and the machine's own firewall
	// posture is left untouched. This is "not managing", NOT "open everything" (we never touch the profile
	// DefaultInboundAction). See the handoff's default-inbound-semantics section.
	if strings.EqualFold(strings.TrimSpace(exp.DefaultAction), "allow") {
		return rules, errs
	}
	for _, r := range exp.Rules {
		if !groupMatches(r.DeviceGroup, deviceGroup) {
			continue
		}
		var action string
		switch strings.ToLower(strings.TrimSpace(r.Action)) {
		case "allow":
			action = "Allow"
		case "deny":
			action = "Block" // Windows evaluates Block before Allow, so an explicit deny wins
		default:
			continue // log / log_alert (observe) — no enforcing rule in v1 (see handoff "Observe")
		}
		var addrs []string
		if src := strings.TrimSpace(r.SourceServer); src != "" {
			if ip, err := netip.ParseAddr(src); err == nil {
				addrs = []string{ip.String()}
			} else if resolve != nil {
				ips, rerr := resolve(src)
				if rerr != nil || len(ips) == 0 {
					errs = append(errs, fmt.Errorf("resolve source_server %q (exception %s): %v — rule omitted (falls under default-deny)", src, r.ExceptionID, rerr))
					continue
				}
				for _, ip := range ips {
					addrs = append(addrs, ip.String())
				}
			} else {
				errs = append(errs, fmt.Errorf("source_server %q is not an IP and no resolver provided (exception %s)", src, r.ExceptionID))
				continue
			}
		}
		fr := fwRule{
			name:        "DSSE-inbound-" + sanitizePSName(r.ExceptionID),
			action:      action,
			protocol:    protoName(r.ServiceFamily),
			remoteAddrs: addrs,
		}
		if fr.protocol != "" && r.Port > 0 && r.Port <= 0xffff {
			fr.port = r.Port // -LocalPort is only valid together with a protocol
		}
		rules = append(rules, fr)
	}
	return rules, errs
}

// firewallReconcileScript renders ONE PowerShell script that clears the DSSE group and re-adds the desired
// rules — a single powershell.exe per reconcile instead of one per rule. Each add is wrapped in try/catch so
// one bad rule cannot abort the rest; failures surface as ADDFAIL lines parsed by the caller.
func firewallReconcileScript(rules []fwRule) string {
	var sb strings.Builder
	// The clear must be try/catch-swallowed, not -ErrorAction SilentlyContinue: in Windows PowerShell 5.1 a
	// suppressed non-terminating error still fails the process exit code. And a swallowed catch as the LAST
	// statement STILL exits 1 — only a succeeding statement after it resets the exit code — which is why the
	// script always ends with the marker line below (a zero-rule reconcile against a not-yet-existing group
	// is otherwise misreported as exit 1 with no output).
	fmt.Fprintf(&sb, "try { Get-NetFirewallRule -Group '%s' -ErrorAction Stop | Remove-NetFirewallRule } catch {}\n", dsseFirewallGroup)
	for _, r := range rules {
		var cmd strings.Builder
		fmt.Fprintf(&cmd, "New-NetFirewallRule -DisplayName '%s' -Group '%s' -Direction Inbound -Action %s -Profile Any -Enabled True",
			r.name, dsseFirewallGroup, r.action)
		if r.protocol != "" {
			fmt.Fprintf(&cmd, " -Protocol %s", r.protocol)
			if r.port > 0 {
				fmt.Fprintf(&cmd, " -LocalPort %d", r.port)
			}
		}
		if len(r.remoteAddrs) > 0 {
			quoted := make([]string, 0, len(r.remoteAddrs))
			for _, a := range r.remoteAddrs {
				quoted = append(quoted, "'"+sanitizePSValue(a)+"'")
			}
			fmt.Fprintf(&cmd, " -RemoteAddress @(%s)", strings.Join(quoted, ","))
		}
		fmt.Fprintf(&sb, "try { %s | Out-Null } catch { Write-Output ('ADDFAIL %s: ' + $_.Exception.Message) }\n", cmd.String(), r.name)
	}
	sb.WriteString("Write-Output '" + fwReconcileDoneMarker + "'\n") // always-succeeding terminal statement (see clear comment)
	return sb.String()
}

// fwReconcileDoneMarker is the script's terminal success line: it both resets the PS 5.1 exit-code quirk above
// and lets the caller distinguish "script ran to completion" from a crash that produced partial output.
const fwReconcileDoneMarker = "DSSE-RECONCILE-COMPLETE"

// reconcileWindowsFirewall materializes the desired rule set as standard Windows Defender Firewall inbound
// rules: clear the DSSE group, then re-add — idempotent, no orphans accumulate across polls.
func reconcileWindowsFirewall(rules []fwRule) error {
	c, err := hiddenPowerShell(firewallReconcileScript(rules))
	if err != nil {
		return fmt.Errorf("firewall reconcile: %w", err)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("firewall reconcile: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), fwReconcileDoneMarker) {
		return fmt.Errorf("firewall reconcile did not run to completion: %s", strings.TrimSpace(string(out)))
	}
	failed := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ADDFAIL ") {
			failed++
			log.Printf("dsse inbound: %s", strings.TrimSpace(line))
		}
	}
	log.Printf("dsse inbound: reconciled Windows Firewall — %d/%d rule(s) in group %q", len(rules)-failed, len(rules), dsseFirewallGroup)
	return nil
}

// fwFingerprint is a change-detection key over the desired rule set (order-stable: export rules are sorted by
// exception_id on the Edge side).
func fwFingerprint(rules []fwRule) string {
	var sb strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&sb, "%s|%s|%s|%d|%s\n", r.name, r.action, r.protocol, r.port, strings.Join(r.remoteAddrs, ","))
	}
	return sb.String()
}

// runInboundNetsh mirrors runInbound (inbound_runtime_windows.go) but reconciles the STANDARD Windows Firewall
// each poll instead of pushing to the WFP driver. The firewall backend is always enforcing (rules are real);
// cfg.enforce is ignored and observe is deferred (handoff v1). Wired in main_windows.go behind
// -inbound-backend=firewall.
func runInboundNetsh(cfg inboundRuntimeConfig) error {
	lastFP := "\x00never" // != any real fingerprint => first pass always reconciles
	sincePush := 0
	reconcile := func() {
		exp, err := loadInboundExport(cfg)
		if err != nil {
			log.Printf("dsse inbound: load export: %v (keeping last applied rules)", err)
			return
		}
		rules, berrs := buildFirewallRules(exp, cfg.deviceGroup, net.LookupIP)
		for _, e := range berrs {
			log.Printf("dsse inbound: rule build warning: %v", e)
		}
		fp := fwFingerprint(rules)
		sincePush++
		if fp == lastFP && sincePush < fwReconcileEvery {
			return // unchanged — skip the delete/recreate flap; periodic forced reconcile self-heals drift
		}
		if err := reconcileWindowsFirewall(rules); err != nil {
			log.Printf("dsse inbound: reconcile: %v", err)
			return
		}
		lastFP, sincePush = fp, 0
	}

	fmt.Printf("inbound: firewall backend active — reconciling group %q (device_group=%q)\n", dsseFirewallGroup, cfg.deviceGroup)
	reconcile()
	defer func() {
		removeDSSEFirewallRules() // cleanup on clean shutdown (a force-kill skips this; --mode recover also clears)
		fmt.Println("inbound: firewall rules cleared")
	}()

	poll := cfg.poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	// Shutdown hook (handoff verify 5): Ctrl+C must run the deferred rule cleanup, not kill the process
	// mid-loop — Go does not run defers on an unhandled interrupt.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	var deadline time.Time
	if cfg.timeout > 0 {
		deadline = time.Now().Add(cfg.timeout)
	}
	for {
		select {
		case <-sig:
			fmt.Println("inbound: interrupt — cleaning up")
			return nil
		case <-ticker.C:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}
		reconcile()
	}
}

// removeDSSEFirewallRules clears the DSSE group (shutdown / backend switch). Best-effort.
func removeDSSEFirewallRules() {
	c, err := hiddenPowerShell(fmt.Sprintf("Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule", dsseFirewallGroup))
	if err != nil {
		// Said out loud: these are inbound ALLOW rules this agent added, and leaving them behind on a box that is
		// no longer steering is a hole nobody knows is open. The group name is the whole recipe for clearing it.
		log.Printf("dsse inbound: the firewall rules in group %q could NOT be removed (%v) — they are still in "+
			"effect on this box and must be cleared by hand", dsseFirewallGroup, err)
		return
	}
	// Bounded (review C-2): powershell/NetSecurity module init can hang in a session-0 recover custom action;
	// a hard timeout keeps a hung child from wedging the msiexec transaction.
	runBounded(c, 20*time.Second)
}

// sanitizePSName / sanitizePSValue strip single quotes (and control chars) so an id/address cannot break out of
// the single-quoted PowerShell literal. The export values originate from admin-authored exceptions, but keep the
// boundary explicit.
func sanitizePSName(s string) string  { return strings.Map(dropUnsafePS, s) }
func sanitizePSValue(s string) string { return strings.Map(dropUnsafePS, s) }

func dropUnsafePS(r rune) rune {
	if r == '\'' || r == '`' || r == ';' || r == '$' || r == '\n' || r == '\r' || r < 0x20 {
		return -1
	}
	return r
}
