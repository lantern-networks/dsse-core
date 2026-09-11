package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// How long a deployment is given to ship its first record before "accepted nothing" means what it says, and
// how often the store is asked meanwhile. Variables, not constants, so the test that proves the NEGATIVE
// ("a store that has accepted nothing fails") does not wait the operator's full 90 seconds to prove it —
// which it did, and was the one test out of 167 that made this package the slowest gate in the tree.
var (
	hotStoreAcceptanceWait = 90 * time.Second
	hotStoreAcceptancePoll = 3 * time.Second
)

// verify_log_path.go — the path a record takes from the node that made it to the authority that keeps it.
//
// ★★★ THE CONTROL PLANE OWNS THREE DURABLE COMPONENTS AND A GENERATED DEPLOYMENT HAD ONE. Postgres
// was there; the hot store and the archive were not, and no Edge was told where to ship. So every record died
// on the node that made it, every report in the Console read an empty store, and nothing said so. A deployment
// that decides and cannot say what it decided is not the product.
//
// ★★ AND THE FAILURE MODE IS THE QUIET ONE. Enforcement does not wait for the log path (invariant 7), so an
// Edge whose history reaches nobody keeps working perfectly — which is right for traffic and worst for the
// operator, who is reading reports that are silently missing a node. That is why this is checked from BOTH
// ends: the node says whether it is delivering, and the authority says whether it is receiving.

// verifyLogPath asks the Edge whether what it records is leaving, and the control plane whether it is landing.
func verifyLogPath(client *http.Client, edgeAdmin, cpAdmin, token string) []verifyResult {
	out := []verifyResult{}

	// The sending end. /healthz reports it because the condition used to exist only in the node's own log.
	code, raw, err := get(client, edgeAdmin+"/healthz", "")
	switch {
	case err != nil || code != 200:
		out = append(out, verifyResult{name: "what this Edge records is reaching the authority",
			note: fmt.Sprintf("%s/healthz -> %d %v", edgeAdmin, code, err)})
	default:
		var body struct {
			AuditShipping *struct {
				Configured   bool   `json:"configured"`
				Delivering   bool   `json:"delivering"`
				Endpoint     string `json:"endpoint"`
				Pending      int64  `json:"pending"`
				Refused      int64  `json:"refused"`
				Dropped      int64  `json:"dropped"`
				LastError    string `json:"last_error"`
				FailingSince string `json:"failing_since"`
			} `json:"audit_shipping"`
		}
		switch {
		case json.Unmarshal(raw, &body) != nil || body.AuditShipping == nil || !body.AuditShipping.Configured:
			out = append(out, verifyResult{name: "what this Edge records is reaching the authority",
				note: "this Edge was never told where to ship. Everything it decides stays on its own disk, " +
					"the control plane's hot store holds nothing it did, and every report in the Console is " +
					"missing this node without saying so"})
		case !body.AuditShipping.Delivering:
			out = append(out, verifyResult{name: "what this Edge records is reaching the authority",
				note: fmt.Sprintf("shipping to %s has been failing since %s (%s) — %d record(s) retained. "+
					"Nothing is lost yet; nothing is arriving either",
					body.AuditShipping.Endpoint, body.AuditShipping.FailingSince,
					first([]byte(body.AuditShipping.LastError), 120), body.AuditShipping.Pending)})
		case body.AuditShipping.Refused > 0 || body.AuditShipping.Dropped > 0:
			// Refused and dropped are different from failing: the channel works and some records will never
			// be accepted. They are set aside rather than lost, and an operator has to know they exist.
			out = append(out, verifyResult{name: "what this Edge records is reaching the authority",
				note: fmt.Sprintf("delivering to %s, but %d record(s) were refused and %d dropped — the channel "+
					"works and those records are not in the authority's history",
					body.AuditShipping.Endpoint, body.AuditShipping.Refused, body.AuditShipping.Dropped)})
		default:
			out = append(out, verifyResult{ok: true, name: "what this Edge records is reaching the authority",
				note: fmt.Sprintf("delivering to %s, %d shipped, none pending", body.AuditShipping.Endpoint,
					body.AuditShipping.Pending)})
		}
	}

	// The receiving end. A store that is reachable and a store that is ACCEPTING are different facts, so this
	// reads the failure counters rather than a status word.
	// ★★★ A DEPLOYMENT MINUTES OLD HAS NOT SHIPPED ANYTHING YET (2026-08-26, found by checking one straight
	// after starting it, which is the printed order). "The hot store has accepted nothing at all" is a
	// serious finding on a running deployment and a meaningless one on a new one: the first record is a
	// flush interval away. Waited for, bounded — and if nothing has arrived by then it is reported exactly as
	// before, because by then it means what it says.
	deadline := time.Now().Add(hotStoreAcceptanceWait)
	for {
		code, raw, err = get(client, cpAdmin+"/admin/hot-store/health", token)
		if err != nil || code != 200 || hotStoreHasAccepted(raw) || time.Now().After(deadline) {
			break
		}
		time.Sleep(hotStoreAcceptancePoll)
	}
	if err != nil || code != 200 {
		out = append(out, verifyResult{name: "the authority keeps what the fleet reports",
			note: fmt.Sprintf("%s/admin/hot-store/health -> %d %v", cpAdmin, code, err)})
		return out
	}
	var health struct {
		Status  string   `json:"status"`
		Reasons []string `json:"reasons"`
		Stats   struct {
			Mirrored       int64 `json:"mirrored"`
			IngestFailures int64 `json:"ingest_failures"`
			DecodeFailures int64 `json:"decode_failures"`
		} `json:"stats"`
		LastFilename  string `json:"last_filename"`
		LastSuccessAt string `json:"last_success_at"`
		LastFailureAt string `json:"last_failure_at"`
		LastError     string `json:"last_error"`
	}
	if err := json.Unmarshal(raw, &health); err != nil {
		out = append(out, verifyResult{name: "the authority keeps what the fleet reports",
			note: fmt.Sprintf("the hot-store health could not be read: %v", err)})
		return out
	}
	// ★★★ A LIFETIME COUNTER IS NOT A STATE (2026-08-28, measured on a deployment that was working). This
	// failed on ingest_failures > 0 — a number that only ever grows — so a store that dropped one batch while
	// its containers were being recreated, and has succeeded on everything since, could never be handed over.
	// It reported
	//
	//	hot store "ok": [] (2 ingest failure(s), 0 decode failure(s))
	//
	// about a store whose own answer said status ok, 143 records, last success THIS SECOND and last failure
	// thirty-five minutes ago. A check that cannot tell "is failing" from "once failed" makes its own verdict
	// worthless: every long-lived deployment eventually fails it and stays failed.
	failing := health.Status != "ok" || newerThan(health.LastFailureAt, health.LastSuccessAt)
	switch {
	case failing:
		out = append(out, verifyResult{name: "the authority keeps what the fleet reports",
			note: fmt.Sprintf("hot store %q: %v (%d ingest failure(s), %d decode failure(s)); last failure %s, "+
				"last success %s: %s", health.Status, health.Reasons, health.Stats.IngestFailures,
				health.Stats.DecodeFailures, health.LastFailureAt, health.LastSuccessAt, health.LastError)})
	case health.Stats.Mirrored == 0:
		out = append(out, verifyResult{name: "the authority keeps what the fleet reports",
			note: "the hot store has accepted nothing at all. A store that is reachable and a store that " +
				"holds this deployment's history are different facts"})
	default:
		// ★ AND A PAST FAILURE IS STILL SAID OUT LOUD. It is not a reason to refuse a handover, and it is
		// something an operator should be able to see rather than have to go looking for.
		note := fmt.Sprintf("%d record(s) in the hot store (%s), and nothing failing now",
			health.Stats.Mirrored, health.LastFilename)
		if health.Stats.IngestFailures > 0 || health.Stats.DecodeFailures > 0 {
			note += fmt.Sprintf(" — %d ingest and %d decode failure(s) in this store's lifetime, the last at %s, "+
				"with a success since", health.Stats.IngestFailures, health.Stats.DecodeFailures, health.LastFailureAt)
		}
		out = append(out, verifyResult{ok: true, name: "the authority keeps what the fleet reports", note: note})
	}
	return out
}

// hotStoreHasAccepted reports whether the hot store has taken at least one record. Reading the same field the
// check below reads, so the wait and the verdict cannot disagree about what "accepted" means.
func hotStoreHasAccepted(raw []byte) bool {
	var health struct {
		Stats struct {
			Mirrored int64 `json:"mirrored"`
		} `json:"stats"`
	}
	return json.Unmarshal(raw, &health) == nil && health.Stats.Mirrored > 0
}

// newerThan answers whether a is a later instant than b, and false when either cannot be read — an unreadable
// timestamp is not evidence of failure.
func newerThan(a, b string) bool {
	at, aerr := time.Parse(time.RFC3339, strings.TrimSpace(a))
	bt, berr := time.Parse(time.RFC3339, strings.TrimSpace(b))
	if aerr != nil || berr != nil {
		return false
	}
	return at.After(bt)
}
