package main

import (
	"fmt"
	"strings"
	"testing"
)

// Found 2026-11-04 by installing docs/plans/single-region.json from the published 0.4.0 images: the containers
// could not resolve the deployment's own names until four alias slots were filled by hand, and the guide's
// host-gateway value did not reach the door, which binds the plan's address.
func TestSingleMachinePlanWritesItsOwnHostAliases(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	m := plan.Regions[0].Machines[0]
	env, err := plan.MachineEnvironment(m.Name)
	if err != nil {
		t.Fatal(err)
	}
	at := m.Addresses[0]
	planes := plan.PlaneNamesFor(plan.Regions[0].ID)
	want := map[string]string{
		"DSSE_HOST_ALIAS_1": m.Reachable + ":" + at,
		"DSSE_HOST_ALIAS_2": planes["agents"] + ":" + at,
		"DSSE_HOST_ALIAS_3": planes["admin"] + ":" + at,
		"DSSE_HOST_ALIAS_4": planes["authority"] + ":" + at,
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
}

func TestMultiMachinePlansLeaveHostAliasesToDNS(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/three-regions.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range plan.MachineNames() {
		env, err := plan.MachineEnvironment(name)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 4; i++ {
			if v, ok := env["DSSE_HOST_ALIAS_"+string(rune('0'+i))]; ok {
				t.Errorf("%s: three-region plan wrote DSSE_HOST_ALIAS_%d=%q; a hosts entry would shadow DNS", name, i, v)
			}
		}
	}
}

// The mint summary must name what the plan's clients dial — the region's names — not names derived from the
// deployment alone that -order never uses.
func TestPlanNameReportListsTheRegionNamesClientsDial(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range planNamesClientsUse(plan) {
		got[n.Name] = n.Address
	}
	planes := plan.PlaneNamesFor(plan.Regions[0].ID)
	at := plan.Regions[0].Machines[0].Addresses[0]
	// console.<deployment> is the origin of the Console's own links (an invitation, a sign-in return); the final
	// acceptance walk of this plan (2026-11-09) had to add it to hosts by hand to open an invitation.
	for _, want := range []string{planes["admin"], planes["authority"], planes["console"], planes["agents"], "recovery." + plan.Deployment, "agents." + plan.Deployment, "console." + plan.Deployment} {
		if got[want] != at {
			t.Errorf("name report: %q -> %q, want %q", want, got[want], at)
		}
	}
	if _, ok := got["admin."+plan.Deployment]; ok {
		t.Errorf("name report lists admin.%s, which -order and the devices never dial", plan.Deployment)
	}
}

// Every door a plan's profiles carry, and every browser Portal name, must be in the report.
func TestPlanNameReportCoversEveryGeneratedDoorAndPortal(t *testing.T) {
	for _, file := range []string{"single-region.json", "three-regions.json", "one-region-three-independent-entries.json", "three-regions-multi-edge.json"} {
		plan, err := LoadPlan("../../docs/plans/" + file)
		if err != nil {
			t.Fatal(file, err)
		}
		listed := map[string]string{}
		for _, n := range planNamesClientsUse(plan) {
			listed[n.Name] = n.Address
		}
		want := []string{}
		for _, entry := range strings.Split(plan.RegionEndpoints(), ";") {
			if _, url, ok := strings.Cut(entry, "="); ok {
				want = append(want, strings.TrimPrefix(url, "https://"))
			}
		}
		want = append(want, plan.BrowserPortalNames()...)
		for _, name := range want {
			at, ok := listed[strings.ToLower(name)]
			if !ok {
				t.Errorf("%s: the name report omits %q", file, name)
			} else if at == "" {
				t.Errorf("%s: the name report gives %q no address", file, name)
			}
		}
	}
}

// With shared_entry_machine moved, the report must put every name where -client-hosts does.
func TestPlanNameReportFollowsTheChosenSharedEntry(t *testing.T) {
	for _, tc := range []struct{ file, shared string }{
		{"one-region-three-independent-entries.json", "node-b"},
		{"three-regions-multi-edge.json", ""},
	} {
		plan, err := LoadPlan("../../docs/plans/" + tc.file)
		if err != nil {
			t.Fatal(tc.file, err)
		}
		if tc.shared == "" {
			// The second control plane of the multi-edge sample.
			for _, r := range plan.Regions[1:] {
				tc.shared = r.controlPlane().Name
				break
			}
		}
		plan.SharedEntryMachine = tc.shared
		if err := plan.Validate(); err != nil {
			t.Fatalf("%s with shared_entry_machine=%s: %v", tc.file, tc.shared, err)
		}
		want := plan.clientHostsAddresses()
		if len(want) == 0 {
			t.Fatalf("%s: no client-hosts addresses", tc.file)
		}
		got := map[string]string{}
		for _, n := range planNamesClientsUse(plan) {
			got[n.Name] = n.Address
		}
		for name, at := range want {
			if got[name] != at {
				t.Errorf("%s (shared %s): %s -> %q in the report, %q in -client-hosts", tc.file, tc.shared, name, got[name], at)
			}
		}
		recovery := planeNamesFor(plan.Deployment).Recovery
		_, m, _ := plan.find(tc.shared)
		if got[recovery] != m.Addresses[0] {
			t.Errorf("%s: %s -> %q, want the chosen shared entry %q", tc.file, recovery, got[recovery], m.Addresses[0])
		}
	}
}

// A one-region three-node plan with a declared shared entry puts every name on that entry.
func TestPlanNameReportPutsEverythingOnADeclaredSharedEntry(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/one-region-three-independent-entries.json")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{}
	for _, m := range plan.Regions[0].Machines {
		targets = append(targets, m.Name)
	}
	plan.Regions[0].Entry = &PlanEntry{Mode: "tcp-pass-through", Targets: targets, PreservesClientIP: true}
	if err := plan.Validate(); err != nil {
		t.Skipf("this plan does not accept a shared entry as written: %v", err)
	}
	names, err := plan.ClientHostNames(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range planNamesClientsUse(plan) {
		got[n.Name] = n.Address
	}
	for _, name := range names {
		if got[strings.ToLower(name)] != sharedRegionEntryAddress {
			t.Errorf("%s -> %q; with a shared entry every name belongs on it", name, got[strings.ToLower(name)])
		}
	}
}

// 0.4.1 final acceptance A (2026-11-09): on one machine the control plane reported its authentication-rollout
// evidence to https://authority.<deployment>, a name its container could not resolve, so the census never
// completed and revocation reauthentication never became active. Whatever the control plane dials for its own
// authority must be a name the containers are given.
func TestASingleMachinesControlPlaneReportsToANameItsContainersResolve(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	env, err := plan.MachineEnvironment(plan.Regions[0].Machines[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	origin := strings.TrimSpace(env["DSSE_AUTH_ROLLOUT_REPORT_ORIGIN"])
	host := strings.TrimPrefix(origin, "https://")
	if origin == "" || host == origin {
		t.Fatalf("the plan does not name where the control plane reports: %q", origin)
	}
	aliased := false
	for i := 1; i <= 4; i++ {
		if name, _, ok := strings.Cut(env[fmt.Sprintf("DSSE_HOST_ALIAS_%d", i)], ":"); ok && name == host {
			aliased = true
		}
	}
	if !aliased {
		t.Fatalf("DSSE_AUTH_ROLLOUT_REPORT_ORIGIN=%s names %s, which no DSSE_HOST_ALIAS gives the containers", origin, host)
	}
}

// On the three-region plan every control plane reports to its own region's authority name, which the names report
// lists — so a deployment whose DNS holds exactly the printed names can complete its census.
func TestEveryRegionsControlPlaneReportsToAListedName(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/three-regions.json")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, n := range planNamesClientsUse(plan) {
		listed[n.Name] = true
	}
	for _, r := range plan.Regions {
		for _, m := range r.Machines {
			env, err := plan.MachineEnvironment(m.Name)
			if err != nil {
				t.Fatal(err)
			}
			host := strings.TrimPrefix(env["DSSE_AUTH_ROLLOUT_REPORT_ORIGIN"], "https://")
			if host == "" || host != plan.PlaneNamesFor(r.ID)["authority"] || !listed[host] {
				t.Fatalf("%s reports to %q; want its region's authority, listed in the names report", m.Name, host)
			}
		}
	}
}
