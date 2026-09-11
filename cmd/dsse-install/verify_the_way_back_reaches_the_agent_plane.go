package main

// verify_the_way_back_reaches_the_agent_plane.go — the recovery name has to land on an Edge.
//
// ★★★ THE ONE NAME NOBODY IS TOLD TO CREATE, AND THE ONLY ONE WHOSE FAILURE IS INVISIBLE (2026-08-27,
// measured on a deployment with one component per machine). The recovery name is in the certificate's SAN
// (main.go), it is written into deployment.env as DSSE_RECOVERY_SNI, and it is announced in the trust bundle
// so devices adopt it while they are healthy. What was missing is every step after that: the installer's list
// of names that must resolve had FOUR entries and recovery was not one of them, and no check here asked where
// it went. So an operator creates the records they were asked for, and the fifth name is created by whoever
// notices it in the certificate — pointed, reasonably and wrongly, at the same machine as admin and console.
//
// Measured on the AWS lab, where the planes are real DNS records rather than container aliases:
//
//	agents.dsse.lab    -> 10.20.1.68   the Edge's machine        openssl: presents the deployment's certificate
//	recovery.dsse.lab  -> 10.20.1.74   the control plane's       openssl: no peer certificate available
//
// The renewal endpoint is served on the AGENT port, so the way back is the agent plane under another name.
// Pointed at the control plane's doorway it reaches a front door that routes admin, authority and console by
// name and sends everything else to an Edge fleet that machine does not have.
//
// ★★★ AND IT HITS ONLY THE DEVICES THAT WERE SWITCHED OFF TOO LONG. Every healthy device renews over the
// certificate it already holds and never sends this name at all, so the deployment reports nothing, the fleet
// looks complete, and the failure arrives one machine at a time, months later, on exactly the machines that
// have no other way in. That is why it is checked here rather than left to be discovered.
//
// Two questions, because they fail differently and the operator needs both answers:
//
//   - WHERE IT GOES. Every address the recovery name resolves to must be one the agent plane's name also
//     resolves to. This is the misconfiguration, named as a misconfiguration, with both answers printed.
//   - WHAT ANSWERS. Dialled with that name as the SNI and verified against the anchor this deployment gives
//     its devices — the handshake an expired agent performs, word for word.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ★ THE TWO THINGS THIS CHECK DOES TO THE WORLD, NAMED SO A TEST CAN DRIVE THE REAL FUNCTION. A test that
// exercised a pure helper beside this one would pass while the call site asked a different question — which
// is how a guard gets written and then silently stops being reached.
var (
	resolvePlaneName = lookupSorted
	dialPlaneName    = func(name, port string, anchor *x509.CertPool) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", net.JoinHostPort(name, port),
			&tls.Config{ServerName: name, RootCAs: anchor, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		return conn.Close()
	}
)

// verifyTheWayBackReachesTheAgentPlane checks the recovery name against the agent plane's. dir is the
// deployment directory holding deployment.env and deployment-anchor.pem; doors are the -edge front doors,
// used only for the port every plane is behind.
func verifyTheWayBackReachesTheAgentPlane(dir string, doors []string) []verifyResult {
	const whereName = "the way back reaches the agent plane"
	const answersName = "the way back answers as itself"

	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return []verifyResult{{name: whereName, note: fmt.Sprintf("could not read this deployment's own description: %v", err)}}
	}
	recovery := strings.TrimSpace(env["DSSE_RECOVERY_SNI"])
	agents := strings.TrimSpace(env["DSSE_AGENT_PLANE_NAME"])
	if recovery == "" {
		// ★ A DEPLOYMENT THAT ANNOUNCES NO WAY BACK STRANDS EVERY DEVICE IT ENROLS, and that is a different
		// failure from pointing it at the wrong machine. It is reported rather than skipped.
		return []verifyResult{{name: whereName, note: "this deployment announces no recovery name " +
			"(DSSE_RECOVERY_SNI is empty), so a device whose certificate expired has nothing to send. Every " +
			"device this deployment enrols is stranded the moment its certificate runs out"}}
	}
	if agents == "" {
		return []verifyResult{{name: whereName, note: "this deployment does not say what its agent plane is " +
			"called (DSSE_AGENT_PLANE_NAME is empty), so where the recovery name SHOULD point cannot be stated"}}
	}
	// ★ AN ADDRESS IS NOT A NAME. A deployment that answers on an address derives every plane as that same
	// address (planeNamesFor), so the two are equal by construction and there is nothing to compare.
	if net.ParseIP(recovery) != nil || strings.EqualFold(recovery, agents) {
		return []verifyResult{{ok: true, name: whereName, note: fmt.Sprintf(
			"this deployment answers on %q rather than on names, so the way back is the agent plane's own address", recovery)}}
	}

	out := []verifyResult{}

	// 1. WHERE IT GOES.
	recoveryAddrs, rerr := resolvePlaneName(recovery)
	agentAddrs, aerr := resolvePlaneName(agents)
	switch {
	case rerr != nil || len(recoveryAddrs) == 0:
		out = append(out, verifyResult{name: whereName, note: fmt.Sprintf(
			"%s does not resolve (%v). It is in this deployment's certificate and in the trust bundle its "+
				"devices adopt, so devices will send it — create the record and point it at the same door as %s",
			recovery, rerr, agents)})
		return out
	case aerr != nil || len(agentAddrs) == 0:
		out = append(out, verifyResult{name: whereName, note: fmt.Sprintf(
			"%s does not resolve (%v), so where %s should point cannot be stated", agents, aerr, recovery)})
		return out
	}
	stray := []string{}
	for _, a := range recoveryAddrs {
		if !contains(agentAddrs, a) {
			stray = append(stray, a)
		}
	}
	if len(stray) > 0 {
		out = append(out, verifyResult{name: whereName, note: fmt.Sprintf(
			"%s -> %s, and the agent plane %s -> %s. The renewal endpoint is served on the AGENT port, so %s "+
				"is the agent plane under another name and must point at the same door. As it stands, the only "+
				"devices that ever send this name — the ones whose certificate has already expired — reach a "+
				"machine that does not serve them, and no healthy device in the fleet touches it, so nothing reports it",
			recovery, strings.Join(recoveryAddrs, ","), agents, strings.Join(agentAddrs, ","), recovery)})
	} else {
		out = append(out, verifyResult{ok: true, name: whereName, note: fmt.Sprintf(
			"%s -> %s, which is where %s goes", recovery, strings.Join(recoveryAddrs, ","), agents)})
	}

	// 2. WHAT ANSWERS. Dialled the way an expired agent dials it.
	anchor, aErr := deploymentAnchorPool(dir)
	if aErr != nil {
		out = append(out, verifyResult{name: answersName, note: fmt.Sprintf(
			"could not read the anchor this deployment gives its devices: %v", aErr)})
		return out
	}
	port := planePortFrom(doors)
	if derr := dialPlaneName(recovery, port, anchor); derr != nil {
		out = append(out, verifyResult{name: answersName, note: fmt.Sprintf(
			"an agent whose certificate expired dials %s:%s with that name and cannot complete the handshake: "+
				"%v. This is the whole of its way back", recovery, port, derr)})
		return out
	}
	out = append(out, verifyResult{ok: true, name: answersName, note: fmt.Sprintf(
		"%s:%s presents a certificate carrying that name and verifying against this deployment's anchor — the "+
			"handshake an expired agent performs", recovery, port)})
	return out
}

// lookupSorted resolves a name to a stable, comparable list of addresses.
func lookupSorted(name string) ([]string, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out, nil
}

// planePortFrom is the port every plane of this deployment is behind, taken from a front door the operator
// named. Every mouth is 443 in production; a lab publishes the door somewhere else and the check must follow
// it rather than assert the production number at it.
func planePortFrom(doors []string) string {
	for _, d := range doors {
		if _, port, err := hostAndPortFromEndpoint(strings.TrimSpace(d)); err == nil && port != "" {
			return port
		}
	}
	return "443"
}
