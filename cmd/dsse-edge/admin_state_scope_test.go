package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
)

// ★★★ A CUSTOMER'S DASHBOARD CARRIED ANOTHER ORGANIZATION'S PEOPLE AND MACHINES (2026-08-16, found by
// sweeping all 120 parameterless admin GET routes as Northwind's administrator). GET /admin/state returned the
// LATEST line of every log stream regardless of whose it was: an access decision naming another organization's
// real user and source IP, a device-state row naming their device, a config generation and a connector
// heartbeat. The route already had the caller's organization in hand — it was simply not used here.
func TestAdminRecentLogsCarryOnlyTheCallersOrganization(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	must(writer.Append("access.log.jsonl", map[string]any{"id": "a1", "tenant_id": "tenant_northwind", "subject_user_id": "nw-user"}))
	must(writer.Append("access.log.jsonl", map[string]any{"id": "a2", "tenant_id": "tenant_reference_lab", "subject_user_id": "WIN-DEV-01\\jdoe"}))
	must(writer.Append("audit.log.jsonl", map[string]any{"id": "u1", "tenant_id": "tenant_reference_lab", "target_id": "win-dev-1"}))

	scoped, err := adminRecentLogs(writer, "tenant_northwind")
	if err != nil {
		t.Fatalf("recent logs: %v", err)
	}
	raw := strings.Join([]string{stringValue(deepField(scoped, "access.log.jsonl", "latest", "subject_user_id"))}, " ")
	if strings.Contains(raw, "WIN-DEV-01") {
		t.Fatalf("another organization's user reached a customer's dashboard: %+v", scoped)
	}
	if got := stringValue(deepField(scoped, "access.log.jsonl", "latest", "id")); got != "a1" {
		t.Fatalf("the caller's own latest row must survive, got %q", got)
	}
	// A stream that holds nothing of theirs must be empty, not filled with somebody else's newest line.
	if latest := deepField(scoped, "audit.log.jsonl", "latest"); latest != nil {
		t.Fatalf("a stream with none of the caller's rows must have no latest, got %+v", latest)
	}

	// The control: an unscoped deployment — one organization, no tenant model — still sees the whole node.
	whole, err := adminRecentLogs(writer, "")
	if err != nil {
		t.Fatalf("recent logs (unscoped): %v", err)
	}
	if got := stringValue(deepField(whole, "audit.log.jsonl", "latest", "id")); got != "u1" {
		t.Fatalf("an unscoped caller must still see the node's own streams, got %q", got)
	}
}

func deepField(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = asMap[p]
	}
	return cur
}

// ★★ THE FOURTH PART OF /admin/state (2026-08-22). Measured as tenant_northwind's administrator — roles
// ["admin"], no cross-organization permission — against the reference control plane: the answer carried
// "policy_bundle":{"id":"bundle_cp_tenant_reference_lab",...}, another customer's organization id, in the
// first screenful of their own dashboard.
func TestTheStateAnswerDoesNotNameAnotherOrganizationsPolicyBundle(t *testing.T) {
	facts := policyBundleFactsForTenant("tenant_reference_lab", "bundle_cp_tenant_reference_lab", "2026.8.1",
		"active", "standard", "tenant_northwind")
	blob, _ := json.Marshal(facts)
	if strings.Contains(string(blob), "reference_lab") {
		t.Fatalf("the answer to another organization still names the bundle's owner: %s", blob)
	}
	// ★ AND IT SAYS SO, rather than reading as "this node has no policy bundle" — a refusal drawn as a zero
	// is the shape this tree keeps finding.
	if strings.TrimSpace(facts["withheld"].(string)) == "" {
		t.Fatal("the identity was withheld silently")
	}

	// ★ THE CONTROLS. Without these this passes for an implementation that withholds from EVERYONE, which
	// would empty the one screen the fields are there for and look identical from the other side.
	own := policyBundleFactsForTenant("tenant_reference_lab", "bundle_cp_tenant_reference_lab", "2026.8.1",
		"active", "standard", "tenant_reference_lab")
	if own["id"] != "bundle_cp_tenant_reference_lab" || own["version"] != "2026.8.1" {
		t.Fatalf("an organization was refused the identity of its OWN policy bundle: %#v", own)
	}
	if _, hidden := own["withheld"]; hidden {
		t.Fatalf("the owner's own answer carries a withholding note: %#v", own)
	}
	// A deployment with no tenant model has no organization to withhold from.
	unscoped := policyBundleFactsForTenant("tenant_reference_lab", "bundle_cp_tenant_reference_lab", "2026.8.1",
		"active", "standard", "")
	if unscoped["id"] != "bundle_cp_tenant_reference_lab" {
		t.Fatalf("a single-tenant deployment lost its own bundle identity: %#v", unscoped)
	}
	// Case-insensitively, the way every other organization comparison in this tree works.
	if _, hidden := policyBundleFactsForTenant("Tenant_Reference_Lab", "b", "v", "active", "standard",
		"tenant_reference_lab")["withheld"]; hidden {
		t.Fatal("a case difference in the organization id was read as a different organization")
	}
}
