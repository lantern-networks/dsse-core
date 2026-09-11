package main

import (
	"fmt"
	"net/http"
	"strings"
)

// verify_front_door.go — whether the region's doorway is a single point.
//
// ★★★ THE AUTHORITY AND ITS DATABASE BOTH SURVIVE LOSING A NODE, AND FOR A WHILE THE DOORWAY DID NOT. A
// deployment that elects a control plane and promotes a database by itself, behind one front-door process, is
// a deployment that survives everything except its own front door. The pair exists for that, and a pair
// nobody measures is a pair that is one misconfiguration away from being a single node with a spare.
//
// ★★ WHAT MAKES A PAIR CHECKABLE AT ALL IS THAT NEITHER DOOR HOLDS ANYTHING. TLS terminates at the Edge, so
// a front door keeps no session a device depends on and the two are interchangeable by construction. That is
// why this check is simply "does each door lead to this deployment" — if the answer is yes for both, either
// one is enough, and there is no further state to compare.
//
// ★★★ AND THE ONE ADDRESS IN FRONT OF THEM IS NOT THIS DEPLOYMENT'S TO DELIVER. A container rendering on one
// host publishes a port from one container; a cloud deployment gets its single address from the platform's
// layer-4 load balancer, and a host deployment from a virtual address moved by VRRP. This checks what the
// deployment controls — that there are two doors and both work — and does not claim the layer below it.

// ★★★ AND A PAIR IS ONE NAME AT TWO ADDRESSES, WHICH THIS COULD NOT BE TOLD (2026-08-28, measured on the
// first deployment whose two doors were both on 443).
//
// Every mouth of this product is 443 and the planes are separated by NAME, so a doorway PAIR is necessarily
// two addresses answering to the same name — that is what the second address is for. Given the second door as
// an address, this dialled https://<address> and the certificate, which carries names, did not match it:
//
//	1 of 2 front door(s) lead to this deployment
//
// on a deployment where both doors answered 200 to the name. The check was right about what it measured — an
// address not in the certificate is not a door a device can use — and had no way to be told the true shape.
// So a door may be written NAME@ADDRESS, which dials the address and verifies the name, the way a device
// resolving that name to either address does.
func frontDoorTarget(door string) (dial, verifyName string) {
	door = strings.TrimRight(strings.TrimSpace(door), "/")
	scheme := "https://"
	rest := door
	if i := strings.Index(door, "://"); i >= 0 {
		scheme, rest = door[:i+3], door[i+3:]
	}
	name, address, found := strings.Cut(rest, "@")
	if !found {
		return door, ""
	}
	return scheme + address, name
}

// verifyFrontDoorPair asks each of the region's front doors whether it leads to an Edge of this deployment.
func verifyFrontDoorPair(client *http.Client, doors []string) []verifyResult {
	live := []string{}
	for _, d := range doors {
		if d = strings.TrimRight(strings.TrimSpace(d), "/"); d != "" {
			live = append(live, d)
		}
	}
	if len(live) < 2 {
		return []verifyResult{{
			name: "the region's doorway is not a single point",
			note: "could not be checked: pass every front door to -edge, comma-separated. One door answering " +
				"says nothing about whether losing it takes the region's agent plane with it",
		}}
	}
	out := []verifyResult{}
	reached := 0
	for _, door := range live {
		// Any HTTP answer proves an EDGE answered: the front door is TCP passthrough and cannot speak HTTP
		// itself. That the response verifies means it presented a certificate this deployment issued — the
		// client is built on the deployment's own anchor.
		dial, name := frontDoorTarget(door)
		req, rerr := http.NewRequest(http.MethodGet, dial+"/healthz", nil)
		if rerr != nil {
			out = append(out, verifyResult{name: "a front door leads to this deployment",
				note: fmt.Sprintf("%s -> %v", door, rerr)})
			continue
		}
		// NAME@ADDRESS: dial the address, and let TLS verify — and the server route — on the name, which is
		// what a device that resolved that name to this address does.
		if name != "" {
			req.Host = name
		}
		resp, err := doorRequest(client, req, name)
		if err != nil {
			out = append(out, verifyResult{
				name: "a front door leads to this deployment",
				note: fmt.Sprintf("%s -> %v", door, err),
			})
			continue
		}
		_ = resp.Body.Close()
		reached++
		out = append(out, verifyResult{
			ok:   true,
			name: "a front door leads to this deployment",
			note: fmt.Sprintf("%s answered %d, and what answered presented this deployment's certificate", door, resp.StatusCode),
		})
	}
	out = append(out, verifyResult{
		ok:   reached >= 2,
		name: "the region's doorway is not a single point",
		note: fmt.Sprintf("%d of %d front door(s) lead to this deployment. Delivering ONE address in front of "+
			"them belongs to the layer below — the platform's layer-4 load balancer, or a virtual address on "+
			"the front-door hosts — and is not established here", reached, len(live)),
	})
	return out
}

// doorRequest sends one request, forcing TLS verification onto the door's NAME while the connection goes to
// the address given. A pair is one name at two addresses; without this the second door can only be dialled
// by an address its certificate does not carry.
func doorRequest(client *http.Client, req *http.Request, name string) (*http.Response, error) {
	if name == "" {
		return client.Do(req)
	}
	cloned := *client
	if base, ok := client.Transport.(*http.Transport); ok && base != nil {
		t := base.Clone()
		if t.TLSClientConfig != nil {
			cfg := t.TLSClientConfig.Clone()
			cfg.ServerName = name
			t.TLSClientConfig = cfg
		}
		cloned.Transport = t
	}
	return cloned.Do(req)
}
