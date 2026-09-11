package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ THE THIRD REPORTED FIELD TO ARRIVE WITH NO READER (2026-08-22).
//
//	2026-08-19  renewal_recovery_sni       shipped by both agents, this struct did not name it
//	2026-08-20  renewal_recovery_target    the rule, the entry field and the Postgres column landed; the
//	                                       struct did not, so every device counted as silent for ever
//	2026-08-22  interception_refusals      win-dev-1 shipped 0.2.21 EV-signed and measured, with a probe
//	                                       that verifies every intercepted chain TWICE and posts what it
//	                                       refused — and this side named no such field, so all of it would
//	                                       have been discarded at the door
//
// Writing it down twice did not work, so this counts instead: every field the Windows agent PUTS on its
// effective report must be named by the struct that decodes it here.
func TestEveryFieldTheAgentReportsHasAReaderHere(t *testing.T) {
	agent, err := os.ReadFile(filepath.Join("..", "..", "clients", "windows-wfp", "steer",
		"steer_exclusion_sync.go"))
	if err != nil {
		t.Skipf("the Windows agent source is not in this tree: %v", err)
	}
	edge, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatalf("read the report handler: %v", err)
	}
	edgeSrc := string(edge)

	// The body the agent POSTs to /steer/agent-policy/effective.
	body := regexp.MustCompile(`(?s)body\s*:?=?\s*struct\s*\{(.*?)\n\t\}`).FindStringSubmatch(string(agent))
	if body == nil {
		// Fall back to the whole file: the point is the json tags it sends, wherever they are declared.
		body = []string{"", string(agent)}
	}
	tags := regexp.MustCompile("`json:\"([a-z0-9_]+)").FindAllStringSubmatch(body[1], -1)
	if len(tags) < 5 {
		t.Fatalf("only %d reported fields found in the agent source — this gate is reading the wrong thing "+
			"and would pass for a tree that reports nothing", len(tags))
	}

	// Fields the Edge deliberately does not read are named here, with the reason, rather than pattern-matched.
	notRead := map[string]string{}

	var missing []string
	seen := map[string]bool{}
	for _, m := range tags {
		field := m[1]
		if seen[field] || notRead[field] != "" {
			continue
		}
		seen[field] = true
		if !strings.Contains(edgeSrc, `json:"`+field+`"`) {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the Windows agent reports %d field(s) this Edge does not decode:\n  %s\n"+
			"A reported field with no reader is the same silence as no field — three times now. Either name "+
			"it in the report handler's body struct, or list it in notRead above with the reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("%d reported fields, all decoded here", len(seen))
}

// And the interception refusals are kept APART from the transport ones, because they are different failures.
func TestInterceptionRefusalsAreNotFoldedIntoTheTransportOnes(t *testing.T) {
	src, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "interceptionRefusals.Merge(tenantID, identity,") {
		t.Fatal("interception refusals are not merged into their own store — merged into the transport list " +
			"they become indistinguishable from a refusal of the Edge's own certificate, which is the " +
			"confusion the device-side journal exists to end")
	}
	if !strings.Contains(s, "normalizeReportedInterceptionRefusals(body.InterceptionRefusals)") {
		t.Fatal("the interception refusals do not go through their own normaliser, so the second verifier's " +
			"objection is truncated at the transport cap — which performs the classification this refuses to do")
	}
	// ★ THE CAP IS THE POINT, so it is pinned.
	obs, err := os.ReadFile("steer_exclusion_observed.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(obs), "normalizeRefusalsWithReasonCap(in, 600)") {
		t.Fatal("the interception reason cap is no longer 600 — win-dev-1's journal caps there because the " +
			"SECOND verifier's disagreement is at the end of the sentence")
	}
}
