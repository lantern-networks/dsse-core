package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// every_edge_is_still_being_configured.go
//
// ★★★ 68/68 ON A DEPLOYMENT WHOSE EVERY EDGE WAS 401 ON EVERY PULL (2026-09-03, measured on a lab stood up
// from nothing an hour earlier).
//
// The fleet credential is minted by -bootstrap-admin and written into deployment.env, and an Edge reads it
// only when it starts. An Edge started BEFORE that bootstrap holds none, and is refused everything
// afterwards: the config bundle, the revocation feed, and the enrolment-token lookup a device needs. It goes
// on serving what it booted with, and every screen says it is healthy.
//
// Nothing caught it, and the reasons are worth keeping:
//
//   - The Edge DOES track this and reports it to the control plane — over the same channel. When the
//     credential is missing that report is 401 too, so the fleet view shows nothing. A node cannot report
//     that it cannot report, and every check reading the fleet view passed.
//   - The one check that asked an Edge directly asked whether it had EVER applied a configuration. That is
//     true forever after the first successful pull at boot, including for a node refused every pull since.
//
// So this asks each Edge, on its own health surface, whether its LAST pull succeeded — a question whose
// answer changes when the thing breaks, reached over a path that does not depend on the thing that is broken.
type edgeConfigPull struct {
	URL         string
	Reachable   bool
	Enabled     bool
	HaveApplied bool
	Generation  uint64
	LastError   string
	LastErrorAt string
	LastPollAt  string
}

// edgeConfigPullState asks one Edge's health surface what its configuration pull is doing.
func edgeConfigPullState(client *http.Client, adminURL string) edgeConfigPull {
	state := edgeConfigPull{URL: strings.TrimRight(adminURL, "/")}
	code, body, err := get(client, state.URL+"/healthz", "")
	if err != nil || code != 200 {
		return state
	}
	state.Reachable = true
	var health struct {
		Role       string `json:"role"`
		ConfigPull struct {
			Enabled     bool   `json:"enabled"`
			HaveApplied bool   `json:"have_applied"`
			Generation  uint64 `json:"last_applied_generation"`
			LastError   string `json:"last_error"`
			LastErrorAt string `json:"last_error_at"`
			LastPollAt  string `json:"last_poll_at"`
		} `json:"config_pull"`
	}
	if json.Unmarshal(body, &health) != nil || health.Role != "edge" {
		state.Reachable = health.Role == "edge"
		return state
	}
	state.Enabled = health.ConfigPull.Enabled
	state.HaveApplied = health.ConfigPull.HaveApplied
	state.Generation = health.ConfigPull.Generation
	state.LastError = strings.TrimSpace(health.ConfigPull.LastError)
	state.LastErrorAt = health.ConfigPull.LastErrorAt
	state.LastPollAt = health.ConfigPull.LastPollAt
	return state
}

// verifyEveryEdgeIsStillBeingConfigured is the check itself.
func verifyEveryEdgeIsStillBeingConfigured(client *http.Client, edgeAdmins []string) []verifyResult {
	const name = "every Edge's last configuration pull succeeded"
	asked, failing, silent := 0, []string{}, []string{}
	for _, url := range edgeAdmins {
		state := edgeConfigPullState(client, url)
		if !state.Reachable {
			continue // a node that cannot be reached is another check's finding, not this one's
		}
		asked++
		switch {
		case !state.Enabled:
			// An authoritative-local node pulls from nobody, and that is not a fault.
			continue
		case state.LastError != "":
			failing = append(failing, fmt.Sprintf("%s (%s, at %s)", state.URL, state.LastError, state.LastErrorAt))
		case state.LastPollAt == "":
			// ★ NEVER POLLED IS NOT THE SAME AS POLLED AND FINE. A node that has applied something at boot
			// and never polled since would otherwise read as healthy.
			silent = append(silent, state.URL)
		}
	}
	if asked == 0 {
		return []verifyResult{{name: name, ok: false, note: "no Edge could be asked, so this says nothing"}}
	}
	sort.Strings(failing)
	sort.Strings(silent)
	if len(failing) > 0 {
		return []verifyResult{{name: name, ok: false, note: fmt.Sprintf(
			"%d of %d Edge(s) were REFUSED their last pull and are serving what they booted with, which every "+
				"other screen reports as healthy: %s. A fleet credential is read only at start-up, so an Edge "+
				"started before -bootstrap-admin holds none — restart the Edges after it",
			len(failing), asked, strings.Join(failing, "; "))}}
	}
	if len(silent) > 0 {
		return []verifyResult{{name: name, ok: false, note: fmt.Sprintf(
			"%d of %d Edge(s) have never polled the control plane: %s", len(silent), asked, strings.Join(silent, ", "))}}
	}
	return []verifyResult{{name: name, ok: true, note: fmt.Sprintf(
		"all %d Edge(s) applied their most recent pull — asked of each node's own health surface, because an "+
			"Edge that cannot reach the authority cannot report that it cannot", asked)}}
}
