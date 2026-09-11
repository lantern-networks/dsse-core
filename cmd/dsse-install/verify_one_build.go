package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_one_build.go — every node of one deployment runs the same build.
//
// ★★★ AN HOUR WENT ON A DEFECT THAT WAS NOT ONE (2026-08-25). A control plane left running an older image
// served stale configuration to the whole fleet: a device removed on the authority was still admitted three
// minutes later, blocking it answered 404, and this very verification reported all three as failures of the
// product. They were failures of one process being a different build, and nothing anywhere could say so.
//
// The reference lab has had a fleet-uniformity check for months — it reads labels off containers. A deployment
// an operator generated has no containers this can inspect, and the question is the same one: are these
// processes the same program?
//
// ★ TWO UNSTAMPED BUILDS HAVE NOT BEEN SHOWN TO AGREE. A plain `go build` reports commit "unknown", and
// treating two of those as a match would pass exactly the deployment this exists to catch.

// verifyOneBuild asks every node which build it is and requires one answer.
func verifyOneBuild(client *http.Client, doors []string) []verifyResult {
	out := []verifyResult{}
	add := func(ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: "every node runs the same build", ok: ok,
			note: fmt.Sprintf(format, args...)})
	}
	byBuild := map[string][]string{}
	unstamped := []string{}
	asked := 0
	for _, door := range doors {
		door = strings.TrimRight(strings.TrimSpace(door), "/")
		if door == "" {
			continue
		}
		code, body, err := get(client, door+"/healthz", "")
		if err != nil || code != 200 {
			add(false, "%s did not answer /healthz (%d %v) — a node that cannot be asked cannot be shown to "+
				"be the same program as the others", door, code, err)
			return out
		}
		var health struct {
			Build *struct {
				Version string `json:"version"`
				Commit  string `json:"commit"`
				Stamped bool   `json:"stamped"`
				Dirty   bool   `json:"dirty"`
			} `json:"build"`
		}
		if json.Unmarshal(body, &health) != nil || health.Build == nil {
			add(false, "%s does not say which build it is — it predates this being reported, which is itself "+
				"the answer: this deployment holds at least one node older than the rest", door)
			return out
		}
		asked++
		if !health.Build.Stamped {
			unstamped = append(unstamped, door)
		}
		key := health.Build.Version + "@" + health.Build.Commit
		if health.Build.Dirty {
			key += "+dirty"
		}
		byBuild[key] = append(byBuild[key], door)
	}
	if asked < 2 {
		add(true, "one node was named, so there is nothing to compare — name the others to measure this")
		return out
	}
	if len(byBuild) > 1 {
		lines := make([]string, 0, len(byBuild))
		for build, nodes := range byBuild {
			sort.Strings(nodes)
			lines = append(lines, fmt.Sprintf("%s: %s", build, strings.Join(nodes, " ")))
		}
		sort.Strings(lines)
		add(false, "this deployment is running %d different builds — %s. A node on an older build serves "+
			"stale configuration to everything that reads from it, and every symptom of that looks like a "+
			"defect in the product", len(byBuild), strings.Join(lines, "; "))
		return out
	}
	if len(unstamped) == asked {
		add(false, "all %d node(s) report an UNSTAMPED build, so they cannot be shown to be the same one — "+
			"build with -ldflags -X main.buildCommit=... so this can be answered", asked)
		return out
	}
	for build := range byBuild {
		add(true, "all %d node(s) run %s", asked, build)
	}
	return out
}
