package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Review FINAL-A-R2 (2026-11-09): the published single-region plan with two more control-plane+Edge machines
// added to the same region, and no profile, is accepted by Validate; the renderer lists neither peers nor
// backends for the extra control planes, so the rendered deployment.env read as one machine and the store check
// was exempted. The plan says three machines, and that is what counts.
func TestAPlanOfSeveralMachinesInOneRegionIsNeverReadAsOne(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	first := plan.Regions[0].Machines[0]
	for i, name := range []string{"node-b", "node-c"} {
		m := first
		m.Name = name
		m.Addresses = []string{"10.20.1.1" + string(rune('1'+i))}
		m.ReachableAddress = m.Addresses[0]
		m.Reachable = name + "." + plan.Deployment
		plan.Regions[0].Machines = append(plan.Regions[0].Machines, m)
	}
	if err := plan.Validate(); err != nil {
		t.Skipf("Validate now refuses this input (%v); the exemption question no longer arises for it", err)
	}
	env, err := plan.MachineEnvironment("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if env["DSSE_CP_PEERS"] != "" || env["DSSE_PG_PEERS"] != "" {
		t.Skip("the renderer now lists the extra control planes as peers; the rendered signals alone would answer")
	}
	dir := t.TempDir()
	host := storeUnder(t, dir, `{"members":[{"name":"dsse-store-region-a","peerURLs":["https://a.example.test:12390"]}]}`)
	env["DSSE_ETCD_CLIENT_SCHEME"] = "https"
	env["DSSE_ETCD_HOSTS"] = "'" + host + "'"
	body := ""
	for k, v := range env {
		body += k + "='" + v + "'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(dir, installPlanFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if deploymentIsASingleMachine(dir) {
		t.Fatal("a plan of three machines was read as one")
	}
	got := verifyTheStoreCanLoseAPlace(dir, readDeploymentEnv(dir))
	if len(got) != 1 || got[0].ok || got[0].name == "the consensus store spans places" {
		t.Fatalf("the store check took the one-machine exemption on a three-machine plan: %+v", got)
	}
	// And the real one-machine plan, with its plan beside it, is still exempt.
	one := t.TempDir()
	single, _ := LoadPlan("../../docs/plans/single-region.json")
	senv, _ := single.MachineEnvironment("node-a")
	body = ""
	for k, v := range senv {
		body += k + "='" + v + "'\n"
	}
	if err := os.WriteFile(filepath.Join(one, "deployment.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(single)
	if err := os.WriteFile(filepath.Join(one, installPlanFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if !deploymentIsASingleMachine(one) {
		t.Fatal("the published single-region plan is no longer read as one machine")
	}
}
