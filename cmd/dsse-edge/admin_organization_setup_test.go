package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★ A NODE MUST NOT CALL AN ORGANIZATION BROKEN ON THE STRENGTH OF A QUESTION IT CANNOT SEE (2026-08-16,
// found by asking both planes). The first version reported a fact this node does not hold as "unavailable"
// AND counted it as blocking, so the control plane said device identity was missing and the organization was
// not operational — while the Edge one desk away answered "1 certificate authority, expires in 1812 days" for
// the same organization. Two planes, contradictory answers, and a screen built on either would have been
// confidently wrong.
func TestAFactThisNodeDoesNotHoldIsNotAGap(t *testing.T) {
	// A control-plane-shaped node: no device CA registry, no interception.
	items := organizationSetupReport(organizationSetupSources{
		Tenant:       adminTenantModel{TenantID: "tenant_northwind", DisplayName: "Northwind"},
		TenantExists: true,
		Evaluator:    decision.Evaluator{},
		Config:       serverConfig{},
		Now:          time.Now(),
	})

	seen := map[string]organizationSetupItem{}
	for _, item := range items {
		seen[item.Key] = item
	}
	for _, key := range []string{"device_identity", "inspection_authority"} {
		item, ok := seen[key]
		if !ok {
			t.Fatalf("%s is not reported at all", key)
		}
		if item.State != organizationSetupNotHere {
			t.Fatalf("%s on a node that does not hold it reads %q", key, item.State)
		}
		if item.Owner != organizationSetupOwnerEdge {
			t.Fatalf("%s does not say which plane can answer it (owner=%q)", key, item.Owner)
		}
	}

	// The control: a fact this node CAN see and the organization has not got still reads as missing, or the
	// checklist would report nothing at all and pass this test by being empty.
	if seen["administrator"].State != organizationSetupMissing {
		t.Fatalf("an organization with no administrator reads %q", seen["administrator"].State)
	}
}

// Every entry has to say what it BUYS you and how to set it, or the checklist is a list of chores and gets
// worked in the order that matters least. The screens are built from these fields, so their absence is not a
// cosmetic problem — it is a screen that can only describe.
func TestEverySetupItemSaysWhatItEnablesAndHowToSetIt(t *testing.T) {
	items := organizationSetupReport(organizationSetupSources{
		Tenant:       adminTenantModel{TenantID: "tenant_northwind"},
		TenantExists: true,
		Evaluator:    decision.Evaluator{},
		Config:       serverConfig{},
		Now:          time.Now(),
	})
	if len(items) < 12 {
		t.Fatalf("the checklist has %d entries; the completion definition has twelve plus the delegation", len(items))
	}
	for _, item := range items {
		if item.Label == "" || item.Enables == "" || item.Detail == "" {
			t.Fatalf("%s is missing label/enables/detail: %+v", item.Key, item)
		}
		if item.Owner == "" {
			t.Fatalf("%s does not say which plane holds it", item.Key)
		}
		// An item this node cannot answer has nothing to offer as an action, and saying so is correct. Every
		// other one must be settable from the screen that shows it.
		if item.State != organizationSetupNotHere && item.Action == nil {
			t.Fatalf("%s is reported and cannot be set — a screen that can only describe is one somebody has "+
				"to leave to get anything done", item.Key)
		}
		if item.Action != nil && (item.Action.Verb == "" || item.Action.Path == "") {
			t.Fatalf("%s has an action with no verb or path: %+v", item.Key, item.Action)
		}
	}
}

// ★ HOLDING A STORE IS NOT OWNING THE FACT (2026-08-16, measured on both planes). The Edge has a local
// admin-credential store, so it answered "no administrator — every change has to go through the operator" for
// an organization with twenty-three of them on the control plane. An empty store on the wrong plane reads
// exactly like an organization nobody has set up, and the two planes' answers were contradictory rather than
// complementary.
func TestANodeAnswersOnlyForTheFactsItsPlaneOwns(t *testing.T) {
	edge := map[string]organizationSetupItem{}
	for _, item := range organizationSetupReport(organizationSetupSources{
		Tenant: adminTenantModel{TenantID: "t", DisplayName: "T"}, TenantExists: true,
		Evaluator: decision.Evaluator{}, Config: serverConfig{}, EnforcementEdge: true, Now: time.Now(),
	}) {
		edge[item.Key] = item
	}
	controlPlane := map[string]organizationSetupItem{}
	for _, item := range organizationSetupReport(organizationSetupSources{
		Tenant: adminTenantModel{TenantID: "t", DisplayName: "T"}, TenantExists: true,
		Evaluator: decision.Evaluator{}, Config: serverConfig{}, EnforcementEdge: false, Now: time.Now(),
	}) {
		controlPlane[item.Key] = item
	}

	// Each plane defers on the other's facts, and neither defers on its own.
	for key, owner := range map[string]string{
		"administrator": organizationSetupOwnerControlPlane,
		"registry":      organizationSetupOwnerControlPlane,
		"enrolment":     organizationSetupOwnerEdge,
		"idp":           organizationSetupOwnerEdge,
	} {
		mine, theirs := edge[key], controlPlane[key]
		if owner == organizationSetupOwnerControlPlane {
			mine, theirs = controlPlane[key], edge[key]
		}
		if theirs.State != organizationSetupNotHere {
			t.Fatalf("%s is owned by the %s and the other plane answered %q for it", key, owner, theirs.State)
		}
		if mine.State == organizationSetupNotHere {
			t.Fatalf("%s is owned by the %s and that plane refused to answer it", key, owner)
		}
	}

	// ★★★ AND ACCESS RULES ARE THE EDGE'S, WHICH THIS TEST USED TO ASSERT THE OPPOSITE OF (2026-09-05,
	// measured on a deployment stood up from the published tree). It required BOTH planes to answer, on the
	// belief that both hold the fact. They do not: the control plane decides nothing for a customer
	// organization and holds no evaluator for one, so it answered "0 rules" — and the checklist told the
	// operator, in a blocking row, "no rules — nothing is enforced for them", while the Edge held the
	// organization's starting rule as one effective policy and the organization's own Internet Access screen
	// showed it as Active.
	//
	//	control plane   effective-policies: 0
	//	edge            effective-policies: 1
	//
	// A row that scores an Edge fact from the control plane cannot be right; it can only be 0.
	if controlPlane["policy"].State != organizationSetupNotHere {
		t.Fatalf("access rules are the enforcement edge's, and the control plane answered %q — it holds no "+
			"evaluator for a customer organization, so any count it gives is 0",
			controlPlane["policy"].State)
	}
	if edge["policy"].State == organizationSetupNotHere {
		t.Fatal("access rules are the enforcement edge's and the edge refused to answer them")
	}
}

// ★ IT COUNTED THE NODE'S RULES, NOT THE ORGANIZATION'S (2026-08-16, seen the moment the wizard created its
// first organization). The first version walked the evaluator's policy bundle, which is whatever the node
// enforces in total — so a brand-new organization with no rules reported "9 rules distributed" and the
// checklist ticked the one item that decides whether anything is enforced for them at all.
//
// A count that is right for the deployment and wrong for the organization is worse than no count: it is a
// green tick on the exact question being asked.
type stubPolicySnapshot map[string]int

func (s stubPolicySnapshot) Snapshot(tenantID string) []model.Policy {
	return make([]model.Policy, s[tenantID])
}

func TestTheRuleCountIsTheOrganizationsNotTheNodes(t *testing.T) {
	// A node enforcing nine rules in total, none of them this organization's.
	evaluator := testEvaluator()
	evaluator.PolicyBundle.PolicyIDs = []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9"}

	report := func(tenant string) organizationSetupItem {
		for _, item := range organizationSetupReport(organizationSetupSources{
			Tenant: adminTenantModel{TenantID: tenant}, TenantExists: true,
			Evaluator: evaluator, Config: serverConfig{}, EnforcementEdge: true,
			Policies: stubPolicySnapshot{"tenant_established": 4},
			Now:      time.Now(),
		}) {
			if item.Key == "policy" {
				return item
			}
		}
		t.Fatalf("no policy item for %s", tenant)
		return organizationSetupItem{}
	}

	fresh := report("tenant_brand_new")
	if fresh.State != organizationSetupMissing {
		t.Fatalf("a brand-new organization with no rules of its own reads %q (%s)", fresh.State, fresh.Detail)
	}
	// The control: an organization that HAS rules still reads as set, or this would pass by reporting nothing.
	established := report("tenant_established")
	if established.State != organizationSetupDone {
		t.Fatalf("an organization with four rules reads %q (%s)", established.State, established.Detail)
	}
	if count, _ := established.Values["count"].(int); count != 4 {
		t.Fatalf("the count is %v, not this organization's four", established.Values["count"])
	}
}

// ★★★ "NOT BLOCKING" MEANT "NOTHING TO ANSWER", AND SETUP CALLED THE ORGANIZATION DONE (letter 105 from
// win-dev-1, on the deployment the installer generates: done 4/13, blocking [], on a deployment where nothing
// has ever inspected anything). A node that cannot see an answer must not supply one — the summary's third
// value exists so "I cannot see this" is neither "fine" nor "broken".
func TestInspectionAuthorityNotHereIsUnseenRatherThanSatisfied(t *testing.T) {
	items := organizationSetupReport(organizationSetupSources{
		Tenant:       adminTenantModel{TenantID: "tenant_default", DisplayName: "Default"},
		TenantExists: true,
		Evaluator:    decision.Evaluator{},
		Config:       serverConfig{}, // no interception engine on this node
		Now:          time.Now(),
	})
	for _, item := range items {
		if item.Key != "inspection_authority" {
			continue
		}
		if item.State != organizationSetupNotHere {
			t.Fatalf("state: got %q", item.State)
		}
		if !item.Blocking {
			t.Fatal("a question this node cannot see must be carried into the summary as UNSEEN — leaving it " +
				"non-blocking makes it evaporate, and the checklist then reads as complete")
		}
		return
	}
	t.Fatal("the inspection authority item is missing entirely")
}
