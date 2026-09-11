package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/bundle"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE DEPLOYMENT REFUSED ITS OWN BUNDLE AND RESTARTED FOR EVER (2026-09-04, found on a running lab whose
// Edge had been crash-looping for an hour):
//
//	load policy bundle: policy bundle checksum mismatch: got sha256:6b28d29… expected sha256:4539e01…
//
// The bundle carries a checksum and a signature over its OWN canonical form, so every field is load-bearing —
// policy_ids included. Adding a policy to the shipped set changes the bundle, and a bundle whose checksum was
// not recomputed cannot start an Edge. Nothing covered writeBundle, so the installer's most fragile output was
// its least tested one.
//
// This asserts what actually matters: the Edge's OWN loader accepts what this installer writes. It calls
// bundle.Validate, not a second implementation of the rules — a private copy would agree today and drift the
// first time the canonical form is touched, which is the failure it is meant to prevent.
func TestTheBundleThisInstallerWritesIsAcceptedByTheEdgesOwnLoader(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeBundle(dir); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if err != nil {
		t.Fatalf("read the bundle the installer wrote: %v", err)
	}
	var b model.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("the installer wrote a bundle that is not valid JSON: %v", err)
	}
	if err := bundle.Validate(b, time.Now()); err != nil {
		t.Fatalf("the Edge would refuse this deployment's own bundle and restart for ever: %v", err)
	}
}

// Every policy the installer ships must be NAMED by the bundle. A policy file that is written, mounted and
// passed to -policy but absent from policy_ids is carried by the deployment and enforced by nothing, which is
// indistinguishable from working until somebody meets the rule it was supposed to add.
func TestEveryShippedPolicyIsNamedByTheBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeSchemasAndPolicy(dir); err != nil {
		t.Fatalf("writeSchemasAndPolicy: %v", err)
	}
	if err := writeBundle(dir); err != nil {
		t.Fatalf("writeBundle: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b model.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	named := map[string]bool{}
	for _, id := range b.PolicyIDs {
		named[id] = true
	}
	matches, err := filepath.Glob(filepath.Join(dir, "policy*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range matches {
		if filepath.Base(path) == "policy-bundle.json" {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("%s is not valid JSON: %v", filepath.Base(path), err)
		}
		if !named[p.ID] {
			t.Fatalf("%s ships policy %q and the bundle does not name it — it would be carried and enforced by nothing", filepath.Base(path), p.ID)
		}
	}
}

// The case that actually happened: a deployment installed before a policy was added to the shipped set. The
// installer must bring its own starting bundle up to date — and the result must still start an Edge, which is
// what a hand-edit could not do.
func bundleMissingAShippedPolicy(t *testing.T, id string) string {
	t.Helper()
	var b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(startingBundle), &b); err != nil {
		t.Fatal(err)
	}
	var policyIDs []string
	if err := json.Unmarshal(b["policy_ids"], &policyIDs); err != nil {
		t.Fatal(err)
	}
	if len(policyIDs) < 2 {
		t.Fatal("fixture needs at least two shipped policies to remove one")
	}
	// shippedPolicyIDs is derived from a map, whose iteration order need not
	// match the JSON text. Edit the document's fields, not its formatting.
	// Preserve the shipped field set, including absent optional fields.
	b["id"], _ = json.Marshal(id)
	b["policy_ids"], _ = json.Marshal(policyIDs[:1])
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAnExistingDeploymentAdoptsANewlyShippedPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o755); err != nil {
		t.Fatal(err)
	}
	stale := bundleMissingAShippedPolicy(t, startingBundleID)
	if err := os.WriteFile(filepath.Join(dir, "policy-bundle.json"), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeBundle(dir); err != nil {
		t.Fatalf("writeBundle over a stale bundle: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b model.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range shippedPolicyIDs {
		if !slices.Contains(b.PolicyIDs, want) {
			t.Fatalf("after the installer ran, the bundle still does not name %q: %v", want, b.PolicyIDs)
		}
	}
	if err := bundle.Validate(b, time.Now()); err != nil {
		t.Fatalf("the rewritten bundle would not start an Edge: %v", err)
	}
}

// And it does not touch a bundle somebody else authored — it says what is missing and stops.
func TestAnAuthoredBundleIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o755); err != nil {
		t.Fatal(err)
	}
	authored := bundleMissingAShippedPolicy(t, "pb_authored_by_the_operator")
	if err := os.WriteFile(filepath.Join(dir, "policy-bundle.json"), []byte(authored), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writeBundle(dir)
	if err == nil {
		t.Fatal("the installer overwrote or silently accepted a bundle it did not write")
	}
	if !strings.Contains(err.Error(), "will not overwrite it") {
		t.Fatalf("the refusal must say why and what to do, got: %v", err)
	}
	after, readErr := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != authored {
		t.Fatal("the authored bundle was modified")
	}
}

// ★ THE CASE THE FIRST ATTEMPT MISSED. The bundle that actually bricked a region NAMED both policies — it had
// been hand-edited, and the edit changed the document without changing the checksum over it. A membership
// check calls that healthy and leaves the deployment exactly as it found it, which is what happened when this
// fix was first run against the real machine. The condition is whether the Edge would start, so the test asks
// the Edge's own loader, and it starts from a bundle that would fail for the same reason the real one did.
func TestAHandEditedBundleIsRewrittenEvenThoughItNamesEveryPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "authority"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Everything named, checksum over something else — a hand-edit.
	broken := strings.Replace(startingBundle,
		`"checksum": "sha256:unsigned-local-bundle"`,
		`"checksum": "sha256:6b28d2935c4abdbdd6bf7672b1572fb7614b43ad7e5f8554aae9c72cc36f63cc"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "policy-bundle.json"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	var before model.PolicyBundle
	if err := json.Unmarshal([]byte(broken), &before); err != nil {
		t.Fatal(err)
	}
	for _, want := range shippedPolicyIDs {
		if !slices.Contains(before.PolicyIDs, want) {
			t.Fatalf("this test must start from a bundle that NAMES everything; it does not name %q", want)
		}
	}
	if err := bundle.Validate(before, time.Now()); err == nil {
		t.Fatal("this test must start from a bundle the Edge would refuse")
	}
	if err := writeBundle(dir); err != nil {
		t.Fatalf("writeBundle over a hand-edited bundle: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var after model.PolicyBundle
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(after, time.Now()); err != nil {
		t.Fatalf("the deployment would still refuse its own bundle and restart for ever: %v", err)
	}
}
