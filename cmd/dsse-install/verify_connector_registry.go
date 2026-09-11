package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// verify_connector_registry.go — every control plane of one deployment holds the SAME connectors.
//
// ★★★ TWO CONTROL PLANES OF ONE DEPLOYMENT ANSWERED 8 AND 1 (2026-08-25, measured on the generated two-region
// lab). The connector registry defaulted to per-process MEMORY on every node, so a registration landed wherever
// the front door happened to route and existed nowhere else. The Console reads whichever control plane answers,
// so an operator refreshing the Sites page saw a site with seven connectors or with one, at random — and every
// registration was lost on restart, which the flag's own help text had warned about for months.
//
// ★ THE CHECK IS ABOUT THE SET, NOT THE COUNT. Two nodes that have both lost everything agree perfectly, and
// that is exactly the state this exists to catch — so an empty deployment is reported as UNMEASURED rather than
// as passing. What is compared is the sorted list of ids: a count can match while the members do not.

// verifyConnectorRegistryIsShared asks every control plane which connectors this deployment has.
func verifyConnectorRegistryIsShared(client *http.Client, cpAdmins []string, token string) []verifyResult {
	out := []verifyResult{}
	add := func(ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: "every control plane holds the same connectors", ok: ok,
			note: fmt.Sprintf(format, args...)})
	}
	doors := []string{}
	for _, u := range cpAdmins {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			doors = append(doors, u)
		}
	}
	if len(doors) < 2 {
		add(true, "one control plane was named, so there is nothing to disagree with — name the peers to measure this")
		return out
	}

	// ★ ONCE PER ORGANIZATION. Connectors belong to CUSTOMER organizations and this check asks with the
	// deployment administrator's token, so asking without naming one measured the operator's own organization
	// and found nothing — see the_deployments_connectors_are_not_the_operators.go.
	organizations := organizationsOfTheDeployment(client, doors[0], token)
	seen := map[string][]string{}
	for _, door := range doors {
		ids, answered := connectorsForEveryOrganization(client, door, token, organizations)
		if !answered {
			add(false, "%s did not answer — a control plane that cannot be asked cannot be shown to agree", door)
			return out
		}
		seen[door] = ids
	}

	first := seen[doors[0]]
	if len(first) == 0 {
		// ★★★ EMPTY IS TWO DIFFERENT ANSWERS AND THIS USED TO GIVE THEM THE SAME ONE (2026-08-26, found by
		// generating a deployment and walking it). "Every node having nothing is the shape of every node
		// having lost everything" is right — and it is ALSO the shape of a deployment nobody has added a
		// connector to yet, which every new deployment is. Reported as a failure, it is a check no fresh
		// install can pass, so an operator following the printed procedure is told their deployment is not
		// ready and has nothing to do about it.
		//
		// The two are distinguishable, and the authority already knows: the enrolled inventory is durable and
		// records every connector this deployment has ever admitted. Nothing there and nothing here is a
		// deployment with no connectors. Something there and nothing here is the loss shape, and it still
		// fails — louder, because now it can say what is missing.
		if ever, known := connectorsTheDeploymentHasAdmitted(client, doors[0], token); known && ever > 0 {
			add(false, "this deployment has admitted %d connector(s) and NO control plane holds any — that is "+
				"the shape of a registry kept in each node's memory, emptied by a restart. The Console reads "+
				"whichever node answers, so a site's connectors appear and disappear on refresh: "+
				"-connector-registry-store=postgres", ever)
			return out
		}
		add(true, "no connector has been added to this deployment yet, and no control plane claims one — "+
			"there is nothing here to be inconsistent about. This becomes a real comparison the moment a "+
			"connector is registered")
		return out
	}
	for _, door := range doors[1:] {
		if strings.Join(seen[door], ",") != strings.Join(first, ",") {
			add(false, "%s holds %d and %s holds %d — the Console reads whichever answers, so a site's "+
				"connectors change on refresh. The registry must be the deployment's database, not each "+
				"node's memory: -connector-registry-store=postgres",
				doors[0], len(first), door, len(seen[door]))
			return out
		}
	}
	add(true, "%d connector(s), the same set on all %d control planes", len(first), len(doors))
	return out
}

// connectorsTheDeploymentHasAdmitted counts the connectors in the durable enrolled inventory — what this
// deployment has ever let in, as opposed to what a node currently holds in the registry. known is false when
// the question could not be asked, so a failure to read is never turned into a number.
func connectorsTheDeploymentHasAdmitted(client *http.Client, door, token string) (count int, known bool) {
	code, body, err := get(client, strings.TrimRight(door, "/")+"/admin/enrolled-devices", token)
	if err != nil || code != 200 {
		return 0, false
	}
	var doc struct {
		Devices []struct {
			Identity string `json:"identity"`
			Kind     string `json:"kind"`
			Note     string `json:"note"`
		} `json:"devices"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return 0, false
	}
	for _, d := range doc.Devices {
		// A connector is recorded as one either by kind or by the note enrolment writes. Both are checked
		// because the kind was added later and older entries carry only the note.
		if strings.EqualFold(strings.TrimSpace(d.Kind), "connector") ||
			strings.Contains(strings.ToLower(d.Note), "as a connector") {
			count++
		}
	}
	return count, true
}
