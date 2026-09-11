//go:build windows

// capture_wfp_inbound.go —  server-initiated (inbound) control-plane contract. Userspace fetches the
// Edge S2 export (server_initiated_export.v1), filters it to THIS device's group, resolves source_server
// hostnames to IPs, and pushes the resulting allow rules + default-deny to the kernel driver via
// DeviceIoControl. The driver evaluates them in its ALE_AUTH_RECV_ACCEPT classify (DsseInboundClassify),
// so a server initiating an inbound connection to this endpoint (the lateral-movement vector) is permitted
// only when an explicit Legacy Exception allows it. Edge is the policy authority ( section 1); the endpoint
// enforces inline (no per-flow kernel->userspace->Edge round-trip). Keep byte-for-byte in lockstep with
// dsse_wfp.h (DSSE_INBOUND_RULE / DSSE_INBOUND_POLICY / DSSE_INBOUND_OBSERVATION / IOCTL 0x804+).
package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"
)

const (
	wfpMaxInboundRules  = 64 // == DSSE_MAX_INBOUND_RULES
	wfpInboundPolicyVer = 1  // == DSSE_INBOUND_POLICY_VERSION
	wfpMaxInboundObs    = 256
)

// wfpInboundRule mirrors DSSE_INBOUND_RULE. SrcAddr is network order (first 4 bytes for IPv4); LocalPort and
// Protocol 0 = wildcard; Action 0=deny, 1=allow.
type wfpInboundRule struct {
	Family    uint32
	SrcAddr   [16]byte
	LocalPort uint16
	Protocol  uint16
	Action    uint32
}

// wfpInboundPolicy mirrors DSSE_INBOUND_POLICY. Enforce: 0 = observe-only (S3a), 1 = enforce (S3b).
type wfpInboundPolicy struct {
	Version     uint32
	DefaultDeny uint32
	Enforce     uint32
	NumRules    uint32
	Rules       [wfpMaxInboundRules]wfpInboundRule
}

// wfpInboundObservation mirrors DSSE_INBOUND_OBSERVATION (drained via IOCTL_DSSE_GET_INBOUND_OBSERVATIONS).
type wfpInboundObservation struct {
	Family     uint32
	ProcessId  uint32
	RemoteAddr [16]byte
	RemotePort uint16
	LocalPort  uint16
	Protocol   uint16
	Action     uint16 // 0=permit (observe/allow), 1=blocked (default-deny)
}

// --- S2 export schema (server_initiated_export.v1) — minimal client view ----------------------------------

type serverInitiatedExportRule struct {
	ExceptionID   string `json:"exception_id"`
	SourceServer  string `json:"source_server"`
	DeviceGroup   string `json:"device_group"`
	ServiceFamily string `json:"service_family"`
	Port          int    `json:"port"`
	Action        string `json:"action"` // allow | deny | log | log_alert
}

type serverInitiatedExport struct {
	SchemaVersion string                      `json:"schema_version"`
	GeneratedAt   string                      `json:"generated_at"`
	DefaultAction string                      `json:"default_action"`
	RuleCount     int                         `json:"rule_count"`
	Rules         []serverInitiatedExportRule `json:"rules"`
	NoSecretAttn  bool                        `json:"no_secret_attestation"`
}

// ipProtoTCP (=6) is declared in steer_core.go and reused here for the service_family->protocol mapping.

// serviceFamilyProtocol maps a Legacy-Exception service_family to its IP protocol. All MVP-Pilot lateral
// protocols (smb/cifs, rdp, winrm, wmi/dcom/rpc, ssh, db, vnc) are TCP; unknown families default to TCP.
func serviceFamilyProtocol(family string) uint16 {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "smb", "cifs", "rdp", "winrm", "wmi", "dcom", "rpc", "ssh", "vnc",
		"mssql", "mysql", "postgres", "oracle", "db", "http", "https", "":
		return ipProtoTCP
	default:
		return ipProtoTCP
	}
}

// exportActionAllows reports whether an export action permits the flow. allow/log/log_alert all PERMIT at the
// kernel (the log/log_alert audit nuance is applied userspace-side); deny is dropped (default-deny covers it).
func exportActionAllows(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "log", "log_alert":
		return true
	default:
		return false
	}
}

// groupMatches reports whether an export rule's device_group applies to this endpoint's group. Empty or "*"
// in the rule = any group; otherwise an exact (case-insensitive) match is required.
func groupMatches(ruleGroup, deviceGroup string) bool {
	rg := strings.ToLower(strings.TrimSpace(ruleGroup))
	if rg == "" || rg == "*" {
		return true
	}
	return rg == strings.ToLower(strings.TrimSpace(deviceGroup))
}

// inboundResolver resolves a source_server hostname to one or more IPs. Pure unit tests pass a stub; runtime
// uses net.LookupIP. A nil resolver means "IP literals only" (hostnames are reported as errors).
type inboundResolver func(host string) ([]net.IP, error)

// buildWFPInboundPolicy converts an S2 export into the kernel inbound policy blob (pure; unit-tested). It
// keeps only rules for this device's group, expands allow rules to one kernel rule per resolved source IP,
// and HONORS the export's default_action for the default disposition. Resolution/parse failures are returned
// as a slice of errors (fail-open per-rule: a rule that cannot be resolved is simply omitted, so it falls
// under the default disposition — never accidentally widened). enforce selects S3a (false=observe) vs S3b
// (true=enforce).
//
// default_action is OPERATOR CONFIG, not a compiled-in literal (no-hardcoded-policy): the netsh firewall backend already
// treats default_action=allow as "DSSE stops managing inbound" (returns no rules, no default-deny). The
// kernel path used to hardcode DefaultDeny=1 regardless, so the two backends diverged and an operator's
// allow-by-default choice was silently overridden on WFP (review #25). Now allow => DefaultDeny=0 + no rules
// (not managing); anything else (deny / empty) keeps the default-deny posture with the built allow rules.
func buildWFPInboundPolicy(exp *serverInitiatedExport, deviceGroup string, resolve inboundResolver, enforce bool) (wfpInboundPolicy, []error) {
	var p wfpInboundPolicy
	p.Version = wfpInboundPolicyVer
	p.DefaultDeny = 1
	if enforce {
		p.Enforce = 1
	}
	var errs []error
	if exp == nil {
		return p, errs
	}
	// Allow-by-default: mirror the netsh backend — DSSE stops managing inbound, so no default-deny and no
	// rules (the machine's own firewall posture is left untouched).
	if strings.EqualFold(strings.TrimSpace(exp.DefaultAction), "allow") {
		p.DefaultDeny = 0
		return p, errs
	}
	add := func(family uint32, src [16]byte, port int, proto uint16) bool {
		if p.NumRules >= wfpMaxInboundRules {
			return false
		}
		var r wfpInboundRule
		r.Family = family
		r.SrcAddr = src
		if port > 0 && port <= 0xffff {
			r.LocalPort = uint16(port)
		}
		r.Protocol = proto
		r.Action = 1 // allow
		p.Rules[p.NumRules] = r
		p.NumRules++
		return true
	}
	for _, rule := range exp.Rules {
		if !groupMatches(rule.DeviceGroup, deviceGroup) {
			continue
		}
		if !exportActionAllows(rule.Action) {
			continue // deny rules are redundant under default-deny
		}
		proto := serviceFamilyProtocol(rule.ServiceFamily)
		// Resolve source_server to IP(s). IP literal => use directly; hostname => resolver.
		var ips []net.IP
		if ip, err := netip.ParseAddr(strings.TrimSpace(rule.SourceServer)); err == nil {
			ips = []net.IP{net.IP(ip.AsSlice())}
		} else if resolve != nil {
			r, rerr := resolve(rule.SourceServer)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("resolve source_server %q (exception %s): %w", rule.SourceServer, rule.ExceptionID, rerr))
				continue
			}
			ips = r
		} else {
			errs = append(errs, fmt.Errorf("source_server %q is not an IP and no resolver provided (exception %s)", rule.SourceServer, rule.ExceptionID))
			continue
		}
		for _, ip := range ips {
			var family uint32
			var src [16]byte
			if v4 := ip.To4(); v4 != nil {
				family = afInet
				copy(src[:4], v4)
			} else if v16 := ip.To16(); v16 != nil {
				family = afInet6
				copy(src[:], v16)
			} else {
				continue
			}
			if !add(family, src, rule.Port, proto) {
				errs = append(errs, fmt.Errorf("inbound rule cap %d reached; dropping further rules", wfpMaxInboundRules))
				return p, errs
			}
		}
	}
	return p, errs
}

// inboundPolicyAllows mirrors the driver's DsseInboundClassify match (pure; for unit tests). srcIP is the
// initiating server. Returns true if an allow rule matches (=> kernel PERMIT), false => default-deny BLOCK.
func inboundPolicyAllows(p *wfpInboundPolicy, srcIP net.IP, localPort uint16, proto uint16) bool {
	var family uint32
	var src [16]byte
	if v4 := srcIP.To4(); v4 != nil {
		family = afInet
		copy(src[:4], v4)
	} else if v16 := srcIP.To16(); v16 != nil {
		family = afInet6
		copy(src[:], v16)
	} else {
		return false
	}
	alen := 16
	if family == afInet {
		alen = 4
	}
	n := p.NumRules
	if n > wfpMaxInboundRules {
		n = wfpMaxInboundRules
	}
	for i := uint32(0); i < n; i++ {
		r := &p.Rules[i]
		if r.Action != 1 || r.Family != family {
			continue
		}
		match := true
		for b := 0; b < alen; b++ {
			if r.SrcAddr[b] != src[b] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if r.LocalPort != 0 && r.LocalPort != localPort {
			continue
		}
		if r.Protocol != 0 && r.Protocol != proto {
			continue
		}
		return true
	}
	return false
}

// --- IOCTL plumbing ---------------------------------------------------------------------------------------

var (
	ioctlWFPSetInboundPolicy   = wfpCtlCode(0x804)
	ioctlWFPClearInboundPolicy = wfpCtlCode(0x805)
	ioctlWFPGetInboundObs      = wfpCtlCode(0x806)
)

// pushInboundPolicy sends the inbound (server-initiated) policy blob to the kernel driver.
func pushInboundPolicy(pol *wfpInboundPolicy) error {
	h, err := openWFPDevice()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	var ret uint32
	return syscall.DeviceIoControl(h, ioctlWFPSetInboundPolicy,
		(*byte)(unsafe.Pointer(pol)), uint32(unsafe.Sizeof(*pol)),
		nil, 0, &ret, nil)
}

// removeInboundPolicy tells the driver to stop enforcing inbound (best-effort).
func removeInboundPolicy() error {
	h, err := openWFPDevice()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	var ret uint32
	return syscall.DeviceIoControl(h, ioctlWFPClearInboundPolicy, nil, 0, nil, 0, &ret, nil)
}

// drainInboundObservations reads (and clears) recorded inbound flows from the driver's observe ring.
func drainInboundObservations() ([]wfpInboundObservation, error) {
	h, err := openWFPDevice()
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)
	buf := make([]byte, 4+wfpMaxInboundObs*int(unsafe.Sizeof(wfpInboundObservation{})))
	var ret uint32
	if err := syscall.DeviceIoControl(h, ioctlWFPGetInboundObs, nil, 0,
		&buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return nil, err
	}
	if ret < 4 {
		return nil, nil
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	recSz := int(unsafe.Sizeof(wfpInboundObservation{}))
	out := make([]wfpInboundObservation, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*recSz
		if off+recSz > len(buf) {
			break
		}
		out = append(out, *(*wfpInboundObservation)(unsafe.Pointer(&buf[off])))
	}
	return out, nil
}
