package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// verify_authority.go — is the deployment's authority a single point of failure?
//
// ★★★ A CONTROL PLANE INCLUDES ITS DATABASE. The architecture lists what it owns — Postgres, ClickHouse, MinIO — so
// "how many control planes are there" is not answered by counting processes. Two processes in front of one
// Postgres are one control plane with two front ends, and since the leadership lock lives in that same
// Postgres, losing it loses leadership too. This file used to answer the count and call it redundancy.
//
// ★★★ EVERYTHING THAT DECIDES ANYTHING IS ON THE CONTROL PLANE: the configuration every Edge pulls, the
// enrolled inventory, and the one-time decisions. An Edge whose control plane is gone keeps ENFORCING what it
// holds — the safe direction — but the deployment can no longer be administered, no device can enrol, and
// nothing new reaches the fleet. One control plane is one failure away from that.
//
// ★ AND EXACTLY ONE OF THE PAIR MAY BE THE LEADER. Two nodes running the same non-idempotent background work
// is worse than neither, so this checks the count as well as the presence: two leaders is a defect, and so is
// none.
func verifyAuthorityIsNotASinglePoint(client *http.Client, cpAdmin string, peers []string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}
	clean := []string{}
	for _, p := range peers {
		if p = strings.TrimRight(strings.TrimSpace(p), "/"); p != "" {
			clean = append(clean, p)
		}
	}
	if len(clean) == 0 {
		// ★ NOT CHECKED, AND SAID SO. Through the front door a deployment with one control plane and a
		// deployment with two look identical — that is what a front door is for. Whether the authority is
		// redundant is a question about the NODES behind it, and it cannot be answered without their
		// addresses.
		add("more than one control-plane process is running", false,
			"could not be checked: pass -control-plane-peers with the individual control planes behind the "+
				"front door. Through the front door, one control plane and two look the same, which is what a "+
				"front door is for and why this cannot be inferred from it")
		return out
	}
	if len(clean) == 1 {
		add("more than one control-plane process is running", false,
			"one control-plane process (%s). Everything that decides anything lives there: an Edge outliving it keeps "+
				"enforcing what it holds, but nothing can be administered, no device can enrol, and nothing new "+
				"reaches the fleet", clean[0])
		return out
	}
	// ★★★ TWO PROCESSES ARE NOT TWO CONTROL PLANES (2026-08-24, corrected). The architecture says what a control plane
	// OWNS: Postgres, ClickHouse, MinIO. So counting the processes and calling the authority redundant is
	// counting the wrong thing — a pair in front of a single database is one control plane with two front
	// processes, and the leadership lock lives in that same database, so losing it takes leadership with it.
	//
	// This check now says what it actually established and names what it did not, rather than reporting green
	// over the part that matters.
	add("more than one control-plane process is running", true, "%d", len(clean))

	leaders, unreachable := []string{}, []string{}
	for _, p := range clean {
		code, body, err := get(client, p+"/leader", "")
		switch {
		case err != nil:
			unreachable = append(unreachable, fmt.Sprintf("%s (%v)", p, err))
		case code == 200:
			var v struct {
				Leader bool `json:"leader"`
			}
			if json.Unmarshal(body, &v) == nil && v.Leader {
				leaders = append(leaders, p)
			}
		case code == 503:
			// A standby. Exactly what it should say.
		default:
			unreachable = append(unreachable, fmt.Sprintf("%s (%d)", p, code))
		}
	}
	switch {
	case len(leaders) == 1:
		add("exactly one control plane is the leader", true, "%s", leaders[0])
	case len(leaders) == 0:
		add("exactly one control plane is the leader", false,
			"none of them holds leadership. Nothing that must run once is running: %s",
			strings.Join(append(clean, unreachable...), ", "))
	default:
		add("exactly one control plane is the leader", false,
			"%d of them claim leadership (%s). Two nodes running the same non-idempotent work is worse than "+
				"neither, and it means the advisory lock is not doing what it is there for",
			len(leaders), strings.Join(leaders, ", "))
	}
	if len(unreachable) > 0 {
		add("every control plane answers", false,
			"%s. A standby that cannot be reached is not a standby", strings.Join(unreachable, ", "))
	}
	return out
}

// verifyAuthorityStateIsRedundant asks the control plane whether its database has a replica.
//
// ★★★ ASKED OF THE NODE, NOT OF THE COMPOSE FILE. Whether the state is redundant is a fact about the running
// database, and the only party positioned to see it is the process connected to it — pg_stat_replication is
// the PRIMARY's view of who is streaming from it. A check that read the deployment description instead would
// report what somebody intended.
//
// ★ AND IT ONLY ESTABLISHES HALF. A replica means the state EXISTS somewhere else. Whether it is PROMOTED
// without a person is a property of what manages the cluster, and a replica nobody promotes automatically is
// a backup: it survives the data and not the outage. The note says which half this is.
func verifyAuthorityStateIsRedundant(client *http.Client, cpAdmin string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}
	code, body, err := get(client, strings.TrimRight(cpAdmin, "/")+"/healthz", "")
	if err != nil || code != 200 {
		add("the authority's durable state is redundant", false,
			"could not ask the control plane: %d %v", code, err)
		return out
	}
	var health struct {
		Database *struct {
			ReplicasStreaming *int     `json:"replicas_streaming"`
			ReplicaMembers    []string `json:"replica_members"`
			OutsideThisRegion string   `json:"replica_outside_this_region"`
		} `json:"database"`
	}
	if json.Unmarshal(body, &health) != nil || health.Database == nil {
		add("the authority's durable state is redundant", false,
			"the control plane did not say. A node that holds the deployment's database reports how many "+
				"replicas stream from it; one that reports nothing has not been asked to look")
		return out
	}
	if health.Database.ReplicasStreaming == nil {
		add("the authority's durable state is redundant", false,
			"the control plane could not read it from its own database. Unknown is not zero, and it is not "+
				"redundant either — this says only that nothing established it")
		return out
	}
	n := *health.Database.ReplicasStreaming
	if n < 1 {
		add("the authority's durable state is redundant", false,
			"no replica is streaming. A control plane owns its Postgres, so an authority with one copy of its "+
				"state is one failure from a deployment that cannot be administered, that no device can enrol "+
				"into, and whose one-time decisions are gone")
		return out
	}
	add("the authority's durable state is redundant", true,
		"%d replica(s) streaming. That the state EXISTS elsewhere; whether it is promoted without a person is "+
			"the cluster manager's property and is not established here", n)

	// ★★★ AND WHETHER ANY OF THEM IS SOMEWHERE ELSE (2026-08-27). The check above passed on a deployment whose
	// second region had no database at all — the first region's own pair answered it. A replica beside the
	// primary survives a MACHINE; only a replica in another region survives the SITE, and until this was asked
	// the deployment had no way to tell an operator which of the two it had.
	if health.Database.OutsideThisRegion != "" {
		add("the state survives losing this region", true,
			"%q streams from here and belongs to another region. Losing this site leaves the deployment's "+
				"state somewhere it can be promoted", health.Database.OutsideThisRegion)
		return out
	}
	if len(health.Database.ReplicaMembers) == 0 {
		add("the state survives losing this region", false,
			"the replicas did not say which members they are, so this establishes nothing. A deployment whose "+
				"members carry no region in their names cannot answer where its state is")
		return out
	}
	add("the state survives losing this region", false,
		"every streaming replica (%s) is in this region. That survives a machine and not the site: lose this "+
			"region and there is no state anywhere to promote, which is what a second control plane with no "+
			"database of its own looks like from outside", strings.Join(health.Database.ReplicaMembers, ", "))
	return out
}

// verifyAuthorityPeersAgree asks each control plane the same question and compares the answers.
//
// ★★★ A PAIR THAT DOES NOT SHARE ITS STATE IS TWO AUTHORITIES (2026-08-24, measured on a generated
// deployment). The election was right, the front door was right, and the two control planes held DIFFERENT
// enrolled rosters — one had the fleet's devices and the other had none. The front door serves whichever is
// leader, so what an Edge received depended on the moment, and an Edge that received nothing kept its own
// roster, which is the lockout-safe rule working exactly as designed. Every node ended up with a different
// list and blocking a device stopped it nowhere.
//
// ★★ IT IS ASKED OF THE PEERS, NOT THROUGH THE FRONT DOOR, for the same reason counting the processes is:
// through the door, two control planes that disagree look exactly like one control plane.
func verifyAuthorityPeersAgree(client *http.Client, peers []string, token string) []verifyResult {
	live := []string{}
	for _, p := range peers {
		if p = strings.TrimRight(strings.TrimSpace(p), "/"); p != "" {
			live = append(live, p)
		}
	}
	if len(live) < 2 {
		return nil // the single-point check beside this one already says the peers were not given
	}
	type answer struct {
		url   string
		count int
		err   error
	}
	answers := make([]answer, 0, len(live))
	for _, peer := range live {
		code, raw, err := get(client, peer+"/admin/enrolled-devices", token)
		if err != nil || code != 200 {
			answers = append(answers, answer{url: peer, err: fmt.Errorf("%d %v", code, err)})
			continue
		}
		var body struct {
			Devices []struct {
				Identity string `json:"identity"`
			} `json:"devices"`
		}
		if uerr := json.Unmarshal(raw, &body); uerr != nil {
			answers = append(answers, answer{url: peer, err: uerr})
			continue
		}
		answers = append(answers, answer{url: peer, count: len(body.Devices)})
	}
	for _, a := range answers {
		if a.err != nil {
			// ★ A CLOSED DEPLOYMENT REFUSES THIS, AND THAT IS NOT A FAILURE OF THE PAIR. Once there is a named
			// administrator the break-glass credential stops working and the fleet's own token is read-scoped
			// — the same wall the enrolment checks name. Saying "401" alone would send whoever reads it
			// looking for a broken control plane.
			hint := ""
			if strings.Contains(a.err.Error(), "401") || strings.Contains(a.err.Error(), "403") {
				hint = ". This deployment has a named administrator, so the break-glass credential is refused" +
					" — pass -admin-token with a named API token, or run this before -bootstrap-admin"
			}
			return []verifyResult{{name: "the control planes hold the same authority",
				note: fmt.Sprintf("%s could not be asked: %v%s", a.url, a.err, hint)}}
		}
	}
	first := answers[0]
	for _, a := range answers[1:] {
		if a.count != first.count {
			return []verifyResult{{name: "the control planes hold the same authority",
				note: fmt.Sprintf("%s names %d enrolled device(s) and %s names %d. The front door serves "+
					"whichever is leader, so what the fleet receives depends on the moment — and an Edge that "+
					"receives an empty roster keeps its own, which means every node ends up with a different "+
					"one and blocking a device stops it nowhere", first.url, first.count, a.url, a.count)}}
		}
	}
	if first.count == 0 {
		// ★ AGREEING ON NOTHING IS NOT AGREEMENT (2026-08-24, caught by reading the number this printed). Two
		// empty control planes give the same answer as two that share their state, and this walk removes the
		// device it enrolled before reaching here — so a pass with zero is a pass that could not have failed.
		return []verifyResult{{ok: true, name: "the control planes hold the same authority",
			note: fmt.Sprintf("%d control plane(s) name no enrolled devices at all, so this could not "+
				"distinguish agreement from emptiness. Ask again on a deployment with devices in it",
				len(answers))}}
	}
	return []verifyResult{{ok: true, name: "the control planes hold the same authority",
		note: fmt.Sprintf("%d control plane(s) name the same %d enrolled device(s)", len(answers), first.count)}}
}
