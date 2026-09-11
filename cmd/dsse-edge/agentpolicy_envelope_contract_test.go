package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The agent-policy envelope schema_version is a CROSS-COMPONENT WIRE CONTRACT: the macOS NE / Windows WFP
// steering agents (the dsse-core agentpolicy client) REJECT any policy whose schema_version differs from
// agentpolicy.EnvelopeType. A real bug shipped here when the OSS rename missed a
// HARDCODED copy of this string in cmd/edge — the edge then served the pre-rename value, the agents rejected
// every policy, and (compounded) steered flows defaulted to deny. Rebuilding never fixed it because the
// wrong value was a literal, not the shared constant.
//
// These two guards make that class of bug non-recurring:
//  1. EnvelopeType is pinned to the exact value the agents expect (changing it is a deliberate wire break), and
//  2. NO product source in this package may hardcode the envelope string as a literal — it must reference the
//     single shared constant, so the edge and the agents can never drift again.
func TestAgentPolicyEnvelopeWireContract(t *testing.T) {
	const expected = "dsse_agent_steer_policy.v1"
	if agentpolicy.EnvelopeType != expected {
		t.Fatalf("agentpolicy.EnvelopeType = %q, want %q — the steering agents pin this exact string; "+
			"if you really mean to change the wire contract, bump it on BOTH sides and update this test",
			agentpolicy.EnvelopeType, expected)
	}

	// No non-test source in cmd/edge may contain the envelope string as a quoted literal: the only correct
	// way to emit it is agentpolicy.EnvelopeType. This used to list the pre-rename spelling alongside it;
	// that spelling is now covered by the whole-word rule below, which does not depend on remembering it.
	forbidden := []string{`"dsse_agent_steer_policy`}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, bad := range forbidden {
				if strings.Contains(line, bad) {
					t.Errorf("%s:%d hardcodes the agent-policy envelope string %s…\"; use agentpolicy.EnvelopeType "+
						"instead (a wire contract must have a single source of truth)", f, i+1, bad)
				}
			}
		}
	}
}

// ★ THIS USED TO BE A LIST OF THREE NAMES, AND THAT IS WHY IT MISSED (2026-08-15). The guard enumerated the
// retired identifiers somebody had thought of — the steer envelope, the CONNECT authority header, the NE
// tunnel headers — so it could only ever catch a regression in one of those three. Four other pre-rename
// literals were sitting in this tree the whole time the guard was green, and one of them was a header the
// edge READ and nothing wrote (an original-uri header under the old brand): the rename moved the writer and
// left the reader, and the reader silently fell through to its second choice for ever.
//
// A list of remembered names cannot catch the one nobody remembered. So the rule is now the rule the
// operator actually stated: the pre-rename brand may not appear in product source AT ALL. Everything below
// is a prefix of that one rule rather than an inventory of past mistakes.
const retiredBrand = "domestic"

// retiredBrandAllowedPaths are the files where the pre-rename brand is still LOAD-BEARING — it names
// something outside this repo that renaming a Go literal would not rename: an identity-provider realm, a
// filename in a device's trust store, an installed path on a customer's disk. Each is a migration with its
// own steps, tracked separately; none of them is a leftover somebody forgot. The point of naming them
// individually is that a NEW file cannot join this set by accident.
var retiredBrandAllowedPaths = map[string]string{
	// The macOS keychain access group and Logger subsystem are baked into SIGNED binaries; changing them
	// costs a re-sign and a re-deploy to every enrolled device, and is gated behind the signing-identity
	// switch that already blocks both platforms.
	"clients/macos-network-extension": "signed-binary identifiers: keychain access group and log subsystem",
	// Back-compat only: the interception root was once written under this filename, and a device that
	// trusted it still has it. The list exists to FIND the old file, so the old name is the whole point.
	"edgeplane/network_extension_tls_interception.go": "legacy trust-store filename, kept to find it",
}

// TestNoStaleRenamedWireContractStrings walks the whole module (product + oss) and fails if the
// pre-rename brand appears in any product source outside the load-bearing set above.
func TestNoStaleRenamedWireContractStrings(t *testing.T) {
	root := filepath.Join("..", "..", "..") // the module root
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if d.Name() == "var" { // var/ = lab scratch / fixtures, not shipped source
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		slashed := filepath.ToSlash(path)
		for allowed := range retiredBrandAllowedPaths {
			if strings.Contains(slashed, allowed) {
				return nil
			}
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(strings.ToLower(line), retiredBrand) {
				t.Errorf("%s:%d still carries the pre-rename brand:\n    %s\n"+
					"  The rename is finished — a leftover here is either a wire identifier whose other end already\n"+
					"  moved (which fails silently, not loudly), or prose. If it genuinely names something outside\n"+
					"  this repo, add it to retiredBrandAllowedPaths with what it names and why it cannot move yet.",
					slashed, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
