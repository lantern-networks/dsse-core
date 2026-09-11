package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★★★ "COMPLETELY DELETED" LEFT A CUSTOMER'S NAMED NETWORKS BEHIND (2026-08-18, measured).
//
// A disposable organization was created on the reference deployment, given one Named Network, deleted, and then
// erased. The erasure answered:
//
//	complete = true, remaining.total = 0
//
// and the Named Network was still there, carrying that organization's id. The footprint counted 34 stores and
// this was not one of them — and a store nobody counts contributes nothing to "what is left", so the answer
// could not have been anything else.
//
// The neighbouring gate (TestTenantFootprintCoversEveryTenantKeyedTable) reads the SCHEMA and demands every
// tenant-keyed Postgres table appear in the list. It is structurally blind to everything that is not a table,
// which is most of what a control plane holds: the durable stores wired through cp_state_blobs. This is its
// sibling for those.
//
// Its own doctrine, quoted from the list it guards: "A table that legitimately holds nothing worth erasing
// still belongs in the list with a count of zero — 'we looked and there was nothing' and 'we never looked' have
// to stay distinguishable."
func TestEveryDurableCPStoreIsCountedOrExcusedInWriting(t *testing.T) {
	// ★ THE PACKAGE IS THE WORKING DIRECTORY (2026-08-23). This named the package by PATH, so it broke
	// the moment the package moved — and it would break again on the published surface, where the
	// same package sits at a different depth. A test binary runs in its own package directory; that
	// is the one fact about the layout that cannot drift.
	root := "."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	// Every store key wired through the shared CP-state blob persister.
	// ★ THE PATTERN MISSED HALF THE CALL SITES, WHICH IS WHAT A GATE MUST NEVER DO (2026-08-18, the day after
	// it was written). It read [cC]p, and the helper most call sites use is mustCPStateBlobPersister — capital
	// P. So the gate saw 18 keys of 29 and passed, giving assurance over stores it had never looked at:
	// catalog_overrides, enrolment_tokens, seat_allocations and three more. A gate that cannot see a thing
	// reports it as fine, which is the same failure the gate exists to catch, one level up.
	key := regexp.MustCompile(`(?:must)?[cC][pP]StateBlobPersister\([^)]*?"([a-z0-9_]+)"`)
	keys := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range key.FindAllStringSubmatch(string(raw), -1) {
			keys[m[1]] = true
		}
	}
	if len(keys) < 25 {
		t.Fatalf("only %d blob store key(s) found — the scan stopped matching, so this gate asserts nothing (it once passed while seeing 18 of 29)", len(keys))
	}

	// Counted: the store appears in the footprint under this name (or the erasure removes it under this name).
	counted := map[string]string{
		// Managed SaaS allowlists in the shared runtime blob are tenant-owned and explicitly erased.
		"admin_runtime_state": "saas_tenant_restrictions",
		"policy_rules":        "authored_rules",
		"enrolled_inventory":  "enrolled_identities",
		"vlan_objects":        "named_networks",
		"catalog_overrides":   "bypass_catalog_overrides",
		// A Site's routes: which of an organization's internal names a connector fronts. Durable since
		// 2026-08-25 — before that they were in memory and an erasure could not miss what a restart already
		// took.
		"connector_route_governance": "connector_route_governance",
		"seat_allocations":           "seat_allocation",
		"policy_candidates":          "policy_candidates",
		"enrolment_tokens":           "enrolment_tokens_store",
		// The organization's own transport authority, held on the control plane so an autoscaled Edge can be
		// handed short-lived server material. It signs the certificate that organization's devices verify, so
		// it is theirs — counted with them, and erased with them.
		"tenant_transport_authorities": "tenant_transport_authorities",
		"tenant_trust_distributions":   "tenant_trust_distributions",
		// Delegated interception: erasing it is how an organization takes back the operator's ability to
		// intercept for them, so it must be counted in what is left.
		"tenant_interception_authorities": "tenant_interception_authorities",
		// What an organization is TOLD to run, and any build published to it alone. Both became visible to
		// this gate the day they moved to shared control-plane state, and neither was counted: a deleted
		// organization left behind its desired version, its incident freeze with the reason a person typed for
		// it, and any canary build — bytes included. The deployment's CATALOGUE is not a tenant's and stays.
		"agent_rollout":         "agent_rollout_plans",
		"agent_updates":         "published_agent_releases",
		"delegated_grants":      "delegated_access_grants",
		"human_approvals":       "human_approvals",
		"grants":                "clientless_grants",
		"idp_connections":       "end_user_idp_connections",
		"high_risk_overlay":     "high_risk_marks",
		"admission_revocations": "admission_kill_switches",
	}

	// ★ Excused, each with the reason it holds nothing a tenant could ask to have erased. An entry here is a
	// PROMISE, and the promise is checkable by reading the store: it is either not tenant-keyed at all, or its
	// contents are rebuilt from configuration on every boot. Anything else belongs in the footprint with a
	// count — including zero.
	excused := map[string]string{

		"audit_chain":               "the tamper-evidence chain over the audit log itself — erasing a tenant must not rewrite the evidence that the erasure happened",
		"legal_hold":                "a legal hold is the one thing that must SURVIVE an erasure request; that is what it is for",
		"retention_override":        "retention windows are per-tenant policy, and an erased tenant's window is removed with its tenant row rather than here",
		"asset_catalog":             "observed assets, re-derived from telemetry; not authored, and refilled by the next report",
		"east_west_observations":    "learned lateral flows, re-derived from telemetry",
		"inspection_events":         "inspection telemetry, aged out by retention rather than owned per tenant",
		"revocation_mesh_outbox":    "in-flight revocation fan-out; entries are consumed, not held",
		"export_download_tokens":    "a download link that has been minted and not yet used: one use, fifteen minutes, and the bytes are dropped the moment it is spent or lapses. It is in flight, not held — the export JOB it came from is the record a tenant can ask about",
		"transport_anchor_acks":     "an operator's assertion that a named node holds one of the deployment's own transport anchors — a statement about the deployment's Edges, not about a tenant, and the record of who opened a withdrawal gate must survive a tenant's erasure for the same reason the audit chain does",
		"transport_trust":           "the anchors THIS DEPLOYMENT distributes for its own Edges, with one serial for the whole fleet — a deployment-level document, not a per-tenant one. An organization's own transport authority is a separate store; erasing a tenant does not change which certificates devices verify an Edge with",
		"inspection_posture":        "the deployment's decrypt posture — one mode and one allowlist for the node, not a per-tenant document; a tenant's erasure does not change which flows this Edge terminates",
		"dlp_allowlist":             "DLP configuration objects; deployment-level, not per tenant",
		"dlp_classifiers":           "DLP configuration objects; deployment-level, not per tenant",
		"dlp_fingerprints":          "DLP configuration objects; deployment-level, not per tenant",
		"dlp_policy_objects":        "DLP configuration objects; deployment-level, not per tenant",
		"entitlements":              "licence entitlements, authored by the operator against a contract rather than held for a tenant to erase",
		"tenant_device_authorities": "the device-identity authority this deployment enrols an organization's fleet with. It is removed with that organization by its own purge step, and erasing one customer must not touch another's",
		"tenant_ca_registry":        "the CERTIFICATE of each organization's own device CA — the customer holds the key and this is the public half the deployment verifies against. It is removed with the organization's own registration, and erasing a customer must not remove another organization's authority",
		"organization_domains":      "domain claims used to route sign-in; removed with the organization's own row",
		"break_glass":               "break-glass requests belong to the OPERATOR who raised one, not to the customer they were raised against — and the mechanism was retired in favour of named credentials, so what is left is evidence of past emergency access rather than a customer's data",
		"vendor_license":            "the deployment's OWN licence from its vendor. It names the operator's contract, not a customer's, and erasing a customer must not touch what the installation is entitled to run",
	}

	var missing []string
	for k := range keys {
		if counted[k] != "" || excused[k] != "" {
			continue
		}
		missing = append(missing, k)
	}
	sort.Strings(missing)

	// Positive control: a key that is neither counted nor excused must be seen, or the comparison only agrees
	// with itself.
	if counted["a_store_that_does_not_exist"] != "" || excused["a_store_that_does_not_exist"] != "" {
		t.Fatal("the control key is present, so this gate proves nothing")
	}

	if len(missing) > 0 {
		t.Fatalf("%d durable control-plane store(s) are in neither the tenant footprint nor the excused list:\n  %s\n\n"+
			"Add the store to countAdminTenantFootprint and to purgeAdminTenantData, or add it to `excused` with "+
			"the reason it holds nothing a tenant could ask to have erased. A store nobody counts contributes "+
			"nothing to \"what is left\", so an erasure over it answers complete=true whatever it still holds — "+
			"which is exactly how a customer's Named Networks survived an erasure that reported remaining.total=0.",
			len(missing), strings.Join(missing, "\n  "))
	}
}
