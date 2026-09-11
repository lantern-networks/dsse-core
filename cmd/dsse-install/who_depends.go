package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// who_depends.go — the inverse of -verify.
//
// ★★★ -verify LOOKS INWARD, AND THAT IS NOT THE QUESTION SOMEBODY ASKS BEFORE STOPPING SOMETHING. It asks
// whether the control plane answers, whether the Edges are applying what it publishes, whether a device can
// enrol. Every one of those can be green while stopping the deployment takes a machine's entire network with
// it.
//
// Written on 2026-08-25, the day that happened. A lab was torn down with permission, and the machine that
// trusted it lost every outbound TCP connection — ICMP still passed, so it read as a working network. Standing
// the deployment back up did not fix it: the transport material the endpoint had pinned lived in the database
// that had been destroyed, and no amount of restarting could reissue it. The only way back was on the machine.
//
// ★★ AND THE DEPLOYMENT HAD BEEN SAYING SO, BY NAME, EVERY TEN MINUTES. The Edge measures which devices have
// adopted the recovery name — the ones that have not are precisely the ones that cannot return — and it
// printed that into a log with no reader. It was correct, and unread, throughout the outage it predicted.
//
// So this asks the outward question, from material that already exists: who trusts this deployment, how many
// of them can come back if it changes underneath them, and how many were relying on it an hour ago.

// dependentsReport is what somebody needs before they stop a deployment.
type dependentsReport struct {
	Enrolled     int
	Endpoints    int
	NoWayBack    []string
	Unmeasured   bool
	SteeringNow  int
	SeenRecently int
}

// verifyWhoDepends assembles the report and renders it as results, so a person reads the same shape they read
// after -verify.
//
// ★ IT IS NOT A PASS/FAIL. Nothing here is a defect: devices depending on a deployment is what a deployment is
// for. What each line has to do is carry a number a person can act on, and say plainly when it could not be
// measured — because "0 devices at risk" and "I could not tell" must never render the same.
// ★★ IT ASKS THE AUTHORITY, NOT A NODE (2026-08-25, found by asking a node). The enrolled roster and the
// fleet's runtime view are the control plane's answers — invariant 1 — and an Edge will not even accept the
// credential a deployment has before it is handed over: an Edge holds no admin auth of its own and
// introspects against the control plane, so the break-glass token, which is that node's own, introspects as
// nothing. Asking an Edge returned 401 for a deployment that was working perfectly.
func verifyWhoDepends(client *http.Client, cpAdmin, token string) []verifyResult {
	out := []verifyResult{}
	edgeAdmin := strings.TrimRight(strings.TrimSpace(cpAdmin), "/")

	// ★★★ AND IT ASKED ABOUT ONE ORGANIZATION (2026-09-01, found on the night this deployment was going to be
	// destroyed with a steer-all, fail-closed Mac still enrolled in it). The roster is scoped to the CALLER's
	// organization and this tool holds the deployment administrator's token, so on a deployment whose devices
	// belong to CUSTOMER organizations — which is every real one — it answered:
	//
	//	ok  who trusts this deployment   nothing is enrolled here, so no machine depends on this deployment
	//
	// while four devices were enrolled and one of them was carrying every flow on the operator's own laptop.
	// The very next line of the same report said "45 device(s) across 6 node(s)", so the report contradicted
	// itself and still rendered a tick. This is the one question asked immediately before an irreversible act,
	// and a wrong "nobody" here is the most expensive wrong answer the tool can give.
	organizations := organizationsOfTheDeployment(client, edgeAdmin, token)
	type enrolledDevice struct {
		Identity string `json:"identity"`
		Enabled  bool   `json:"enabled"`
		Kind     string `json:"kind"`
	}
	seen := map[string]enrolledDevice{}
	answered := false
	for _, org := range organizations {
		endpoint := edgeAdmin + "/admin/enrolled-devices"
		if org != "" {
			endpoint += "?tenant_id=" + url.QueryEscape(org)
		}
		code, raw, err := get(client, endpoint, token)
		if err != nil || code != 200 {
			continue
		}
		answered = true
		var inventory struct {
			Devices []enrolledDevice `json:"devices"`
		}
		if json.Unmarshal(raw, &inventory) != nil {
			continue
		}
		for _, d := range inventory.Devices {
			if id := strings.TrimSpace(d.Identity); id != "" {
				seen[id] = d
			}
		}
	}
	if !answered {
		return append(out, verifyResult{name: "who trusts this deployment",
			note: "could not be counted: GET /admin/enrolled-devices did not answer for any organization"})
	}
	rep := dependentsReport{Enrolled: len(seen)}
	for _, d := range seen {
		if !strings.EqualFold(strings.TrimSpace(d.Kind), "connector") {
			rep.Endpoints++
		}
	}
	switch rep.Enrolled {
	case 0:
		// ★ SAYING "0 devices, each of which..." IS HOW A REPORT STOPS BEING READ. Nothing trusts this yet, and
		// that is the one case where stopping it costs nobody anything.
		out = append(out, verifyResult{ok: true, name: "who trusts this deployment",
			note: "nothing is enrolled here, so no machine depends on this deployment"})
	default:
		out = append(out, verifyResult{ok: true, name: "who trusts this deployment",
			note: fmt.Sprintf("%d enrolled identity(ies), of which %d are endpoints. Each holds a certificate "+
				"this deployment issued and reaches the world through it", rep.Enrolled, rep.Endpoints)})
	}

	// ★★★ THE ONE THAT MATTERS BEFORE A DESTRUCTIVE ACT. A device that has not adopted the recovery name has
	// no way back if what it trusts changes.
	// ★★★ ASKED OF THE AUTHORITY, ANSWERED BY THE EDGES (2026-08-25). Devices meet Edges; the control plane
	// serves no agent plane, so its OWN recovery readiness is about a node no device has ever dialled —
	// structurally empty, and reassuring. Each Edge reports whether it offers a way back and how many of its
	// devices have not taken it, in the fleet status it already sends, and this reads that. Observation is
	// the Edge reporting, never the reader asking an Edge.
	code, raw, err := get(client, edgeAdmin+"/admin/fleet/config-status", token)
	if err == nil && code == 200 {
		// ★ THE OPERATOR'S VIEW, WHICH IS THE ONE THAT CARRIES NODES. A caller scoped to one organization is
		// answered with a narrowed projection that deliberately says nothing about which node it is or what
		// else that node carries — right for a customer, and empty for this question.
		var fleet struct {
			// ★★★ AND WHETHER THAT VIEW IS THE FLEET (2026-08-25, measured). This answer is read BEFORE
			// somebody destroys something, and its reassuring branch — "every device on all N nodes has been
			// measured onto a recovery name" — divides by N. A control plane promoted moments ago holds only
			// what has reached it since: fifteen seconds after a failover the view carried two of four Edges
			// and reported them in sync. Being told everyone can come back, over half a fleet, immediately
			// before a destructive act, is the worst shape this answer can take.
			Formed *bool `json:"fleet_view_formed"`
			Edges  []struct {
				RegionID     string `json:"region_id"`
				ClusterID    string `json:"cluster_id"`
				RecoveryName string `json:"recovery_name"`
				Without      int    `json:"devices_without_a_way_back"`
			} `json:"edges"`
		}
		if json.Unmarshal(raw, &fleet) == nil && fleet.Formed != nil && !*fleet.Formed {
			out = append(out, verifyResult{name: "how many of them can come back",
				note: fmt.Sprintf("the authority's view of the fleet is still forming (%d node(s) so far). "+
					"A node that has not reported yet looks exactly like one that is gone, so this was NOT "+
					"measured — ask again shortly, and do not destroy anything on the strength of it",
					len(fleet.Edges))})
		} else if json.Unmarshal(raw, &fleet) == nil && len(fleet.Edges) > 0 {
			noName, stranded, nodes := []string{}, 0, 0
			for _, n := range fleet.Edges {
				nodes++
				where := strings.TrimSpace(n.RegionID + "/" + n.ClusterID)
				if strings.TrimSpace(n.RecoveryName) == "" {
					noName = append(noName, where)
					continue
				}
				stranded += n.Without
			}
			switch {
			case len(noName) == nodes && stranded == 0 && !operatorScoped(fleet.Edges):
				// ★ AND SAY WHICH QUESTION COULD NOT BE ASKED. A credential scoped to one organization is
				// answered with a projection that deliberately withholds node facts, so "how many devices"
				// is invisible — but the NAME is not, and its absence on every node is the alarming half.
				out = append(out, verifyResult{name: "how many of them can come back",
					note: fmt.Sprintf("no node in this deployment offers a way back (%d node(s) report no "+
						"recovery name). How MANY devices that strands is the node's own figure and needs an "+
						"operator-scoped credential to read", nodes)})
			case len(noName) > 0:
				out = append(out, verifyResult{name: "how many of them can come back",
					note: fmt.Sprintf("%d of %d node(s) offer NO way back at all (%s). A device that enrolled "+
						"there depends on its current certificate continuing to work, and cannot return by "+
						"itself if it does not", len(noName), nodes, strings.Join(noName, ", "))})
			case stranded > 0:
				out = append(out, verifyResult{name: "how many of them can come back",
					note: fmt.Sprintf("%d device(s) across %d node(s) have not been measured onto the recovery "+
						"name. Silence counts here: a machine that is switched off is exactly the one that "+
						"path exists for", stranded, nodes)})
			default:
				out = append(out, verifyResult{ok: true, name: "how many of them can come back",
					note: fmt.Sprintf("every device on all %d node(s) has been measured onto a recovery name",
						nodes)})
			}
			return append(out, whoDependsRuntime(client, edgeAdmin, token, rep)...)
		}
	}
	code, raw, err = get(client, edgeAdmin+"/admin/recovery-readiness", token)
	switch {
	case err != nil || code != 200:
		rep.Unmeasured = true
		out = append(out, verifyResult{name: "how many of them can come back",
			note: fmt.Sprintf("could not be measured: GET /admin/recovery-readiness -> %d %v. \"None at risk\" "+
				"and \"I could not tell\" are different answers and this is the second one", code, err)})
	default:
		var body struct {
			Measured  bool `json:"measured"`
			Readiness struct {
				Name        string   `json:"name"`
				Holds       []string `json:"holds"`
				DoesNotHold []string `json:"does_not_hold"`
				Silent      []string `json:"silent"`
				Never       []string `json:"never_reported_anything"`
			} `json:"readiness"`
		}
		if uerr := json.Unmarshal(raw, &body); uerr != nil || !body.Measured {
			// ★★★ AND THIS IS THE ALARMING CASE, NOT THE REASSURING ONE (2026-08-25, caught by reading what
			// this printed next to a count of 2). No recovery name announced means there is no name for a
			// device to hold — so EVERY enrolled machine has no way back, not none of them. The first version
			// of this line said "none is at risk", which is true only when nothing is enrolled, and would have
			// reassured somebody in exactly the situation that produced this check.
			if rep.Enrolled == 0 {
				out = append(out, verifyResult{ok: true, name: "how many of them can come back",
					note: "no recovery name is announced, and nothing is enrolled, so there is nobody to " +
						"strand"})
				break
			}
			out = append(out, verifyResult{name: "how many of them can come back",
				note: fmt.Sprintf("NONE of the %d. This deployment announces no recovery name at all, so there "+
					"is no name for a device to hold — every one of them depends on its current certificate "+
					"continuing to work, and cannot return by itself if it does not", rep.Enrolled)})
			break
		}
		at := map[string]bool{}
		for _, id := range append(append([]string{}, body.Readiness.DoesNotHold...),
			append(body.Readiness.Silent, body.Readiness.Never...)...) {
			if id = strings.TrimSpace(id); id != "" {
				at[id] = true
			}
		}
		for id := range at {
			rep.NoWayBack = append(rep.NoWayBack, id)
		}
		sort.Strings(rep.NoWayBack)
		if len(rep.NoWayBack) == 0 {
			out = append(out, verifyResult{ok: true, name: "how many of them can come back",
				note: fmt.Sprintf("every device holds %s, so each has a way back if its certificate breaks",
					body.Readiness.Name)})
			break
		}
		// ★ SILENCE COUNTS AS "NO". A device that has not reported is the one this path exists for — it may be
		// switched off, and it is exactly the machine nobody will be watching when it fails to return.
		out = append(out, verifyResult{name: "how many of them can come back",
			note: fmt.Sprintf("%d of %d have NOT adopted %s: %s. If this deployment stops, or what it presents "+
				"changes, those machines cannot return by themselves — somebody has to go to each of them",
				len(rep.NoWayBack), rep.Enrolled, body.Readiness.Name, strings.Join(rep.NoWayBack, ", "))})
	}

	return append(out, whoDependsRuntime(client, edgeAdmin, token, rep)...)
}

// whoDependsRuntime answers how many were relying on this deployment recently, which is the difference
// between a list of names and a consequence.
func whoDependsRuntime(client *http.Client, edgeAdmin, token string, rep dependentsReport) []verifyResult {
	out := []verifyResult{}
	code, raw, err := get(client, edgeAdmin+"/admin/device-runtime", token)
	if err != nil || code != 200 {
		return append(out, verifyResult{name: "how many were relying on it in the last hour",
			note: fmt.Sprintf("could not be measured: GET /admin/device-runtime -> %d %v", code, err)})
	}
	var runtime map[string]struct {
		SteerActive bool   `json:"steer_active"`
		LastSeen    string `json:"last_seen"`
	}
	if uerr := json.Unmarshal(raw, &runtime); uerr != nil {
		// The shape differs between versions; a wrapper is common. Report the miss rather than a zero.
		var wrapped struct {
			Devices map[string]struct {
				SteerActive bool   `json:"steer_active"`
				LastSeen    string `json:"last_seen"`
			} `json:"devices"`
		}
		if json.Unmarshal(raw, &wrapped) != nil || wrapped.Devices == nil {
			return append(out, verifyResult{name: "how many were relying on it in the last hour",
				note: fmt.Sprintf("the device-runtime answer could not be read: %v", uerr)})
		}
		runtime = wrapped.Devices
	}
	hour := time.Now().Add(-time.Hour)
	for _, d := range runtime {
		if d.SteerActive {
			rep.SteeringNow++
		}
		if at, perr := time.Parse(time.RFC3339, strings.TrimSpace(d.LastSeen)); perr == nil && at.After(hour) {
			rep.SeenRecently++
		}
	}
	out = append(out, verifyResult{ok: true, name: "how many were relying on it in the last hour",
		note: fmt.Sprintf("%d steering now, %d seen in the last hour. A machine that is switched off is not on "+
			"this list and is affected exactly the same", rep.SteeringNow, rep.SeenRecently)})
	return out
}

// runWhoDepends is the mode. It prints and never exits non-zero: nothing it reports is a defect, and an
// operator reading a number should not have to distinguish "this failed" from "this is what you have".
func runWhoDepends(dir, cpAdmin, adminToken string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("-dir is required: this reads the deployment's own anchor to reach its nodes")
	}
	if strings.TrimSpace(cpAdmin) == "" {
		return fmt.Errorf("-control-plane is required: the roster and the fleet's runtime view are the " +
			"authority's answers, and an Edge will not accept a break-glass credential — it holds no admin " +
			"auth of its own")
	}
	client, err := deploymentClient(dir)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(adminToken)
	if token == "" {
		if env, eerr := readEnvFile(filepath.Join(dir, "deployment.env")); eerr == nil {
			token = strings.TrimSpace(env["ADMIN_TOKEN"])
		}
	}
	first := strings.TrimSpace(strings.Split(cpAdmin, ",")[0])
	fmt.Printf("dsse-install -who-depends: %s\n\n", first)
	for _, r := range verifyWhoDepends(client, first, token) {
		mark := "  ok  "
		if !r.ok {
			mark = "  ★   "
		}
		fmt.Printf("%s%-44s %s\n", mark, r.name, r.note)
	}
	fmt.Printf("\n  ★ NONE OF THIS IS A FAILURE. It is what stopping this deployment costs, which is a\n")
	fmt.Printf("  different question from whether it is correct — and the only one worth asking first.\n")
	return nil
}

// operatorScoped reports whether this answer carried node facts — the projection a customer receives
// deliberately omits them, and a reader that cannot tell will report "0" for "I was not shown".
func operatorScoped(edges []struct {
	RegionID     string `json:"region_id"`
	ClusterID    string `json:"cluster_id"`
	RecoveryName string `json:"recovery_name"`
	Without      int    `json:"devices_without_a_way_back"`
}) bool {
	for _, e := range edges {
		if strings.TrimSpace(e.ClusterID) != "" {
			return true
		}
	}
	return false
}
