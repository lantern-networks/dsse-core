package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ★★★ A DOOR THAT CAN REACH THE LEADER ONLY THROUGH THE LEADER'S OWN DOOR (2026-11-06). Measured on a
// three-region deployment: with region-a's front door stopped and its control plane still leading, every
// other region's Console answered 502 at sign-in. The doors now reach each other control plane at its own
// private listener (DSSE_CP_PEERS, port 19543) and keep the other regions' doorways only as backups.
//
// ★ AND THAT IS INVISIBLE WHEN THE LISTENER IS FIREWALLED. A door whose direct peers never come up uses the
// backups and works — until the day a doorway is the thing that fails, which is exactly the day it matters.
// So -verify asks each direct peer itself, from here, the way a door on this machine would: dial the address,
// verify the control plane's certificate by the name the door checks, GET /leader. 200 (leading) and 503
// (standing by) both mean the listener answered; anything that does not finish a verified exchange does not.
func verifyEachControlPlaneAnswersAtItsOwnListener(client *http.Client, env map[string]string) []verifyResult {
	out := verifyControlPlanesAnswerAtPort(client, env, fmt.Sprint(planCPAdminPortA))
	return append(out, verifyDataListenersAnswer(client, env, fmt.Sprint(planCPDataPortA))...)
}

// verifyDataListenersAnswer asks each other control plane's DATA listener (19545) the question the doors ask it:
// GET /healthz, answered without a client certificate. The admin listener answering says nothing about this one
// — a firewall can close one and not the other (2026-11-06), and then every write a node ships to
// that region fails while its leader check stays green.
func verifyDataListenersAnswer(client *http.Client, env map[string]string, dataPort string) []verifyResult {
	const name = "the other control planes' data listeners answer"
	var direct []string
	for _, p := range strings.Split(env[controlPlaneDataPeersKey], ",") {
		p = strings.TrimSpace(p)
		if _, address, found := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://"), "@"); found {
			if _, port, err := net.SplitHostPort(address); err == nil && port == dataPort {
				direct = append(direct, p)
			}
		}
	}
	if len(direct) == 0 {
		return nil
	}
	answered, notes := 0, []string{}
	for _, peer := range direct {
		dial, tlsName := frontDoorTarget(peer)
		req, err := http.NewRequest(http.MethodGet, dial+"/healthz", nil)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s -> %v", peer, err))
			continue
		}
		req.Host = tlsName
		resp, err := doorRequest(client, req, tlsName)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s -> %v", peer, err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			notes = append(notes, fmt.Sprintf("%s -> answered %d to GET /healthz", peer, resp.StatusCode))
			continue
		}
		answered++
		notes = append(notes, fmt.Sprintf("%s -> 200", peer))
	}
	note := fmt.Sprintf("%d of %d answered directly (%s)", answered, len(direct), strings.Join(notes, "; "))
	if answered < len(direct) {
		note += fmt.Sprintf(". Allow TCP %d between the control-plane machines' addresses (see Network access in "+
			"docs/deployment.md): while it is closed, writes to that region go through its doorway only when no "+
			"direct control plane answers at all", planCPDataPortA)
	}
	return []verifyResult{{name: name, ok: answered == len(direct), note: note}}
}

func verifyControlPlanesAnswerAtPort(client *http.Client, env map[string]string, directPort string) []verifyResult {
	const name = "the other control planes answer at their own listeners"
	var direct []string
	for _, p := range strings.Split(env[controlPlanePeersKey], ",") {
		p = strings.TrimSpace(p)
		rest := strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://")
		_, address, found := strings.Cut(rest, "@")
		if !found {
			continue
		}
		if _, port, err := net.SplitHostPort(address); err == nil && port == directPort {
			direct = append(direct, p)
		}
	}
	if len(direct) == 0 {
		// One control plane, or a deployment rendered before the doors addressed control planes directly.
		return nil
	}
	answered, notes := 0, []string{}
	for _, peer := range direct {
		dial, tlsName := frontDoorTarget(peer)
		req, err := http.NewRequest(http.MethodGet, dial+"/leader", nil)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s -> %v", peer, err))
			continue
		}
		req.Host = tlsName
		resp, err := doorRequest(client, req, tlsName)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s -> %v", peer, err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
			notes = append(notes, fmt.Sprintf("%s -> answered %d to GET /leader", peer, resp.StatusCode))
			continue
		}
		answered++
		notes = append(notes, fmt.Sprintf("%s -> %d", peer, resp.StatusCode))
	}
	note := fmt.Sprintf("%d of %d answered directly (%s)", answered, len(direct), strings.Join(notes, "; "))
	if answered < len(direct) {
		note += fmt.Sprintf(". The doors fall back to the other regions' doorways, so this works today and stops "+
			"the day a doorway fails while its control plane still leads. Allow TCP %d and %d between the "+
			"control-plane machines' addresses (see Network access in docs/deployment.md)",
			planCPAdminPortA, planCPDataPortA)
	}
	return []verifyResult{{name: name, ok: answered == len(direct), note: note}}
}
