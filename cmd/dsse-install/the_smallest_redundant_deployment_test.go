package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE SMALLEST DEPLOYMENT THAT SURVIVES A FAILURE HAS TO BE DECLARABLE (2026-08-31).
//
// The canonical architecture answers "how small can this be" with a table: surviving the loss of one region
// costs THREE state-bearing regions, because a quorum needs three voting places. Voting places, not machines
// — so one machine per region, each holding the control plane and the Edges, is three machines and survives
// the loss of any one of them, while four machines in two regions survives nothing at the authority layer.
// The shape with fewer machines is the one with redundancy.
//
// That shape needs a machine to hold both components, and the plan could only say one. The renderer has had
// the both-shape since the beginning as the one-host reference; what was missing was the vocabulary.
func TestThreeRegionsOfOneMachineEachIsAValidPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{
	  "deployment": "example.test",
	  "regions": [
	    {"id":"a","founding":true,"holds_state":true,"machines":[
	      {"name":"node-a","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"],
	       "reachable":"node-a.example.test","reachable_address":"203.0.113.1"}]},
	    {"id":"b","holds_state":true,"machines":[
	      {"name":"node-b","holds":["control-plane","edges"],"addresses":["10.0.1.1","10.0.1.2"],
	       "reachable":"node-b.example.test","reachable_address":"203.0.113.2"}]},
	    {"id":"c","holds_state":true,"machines":[
	      {"name":"node-c","holds":["control-plane","edges"],"addresses":["10.0.2.1","10.0.2.2"],
	       "reachable":"node-c.example.test","reachable_address":"203.0.113.3"}]}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatalf("the smallest redundant deployment does not load: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("the smallest redundant deployment is refused: %v", err)
	}
	for _, r := range p.Regions {
		m := r.Machines[0]
		if !m.Holds.has("control-plane") || !m.Holds.has("edges") {
			t.Errorf("region %s: machine %s holds %v, and both were asked for", r.ID, m.Name, m.Holds)
		}
	}
}

// ★ A PLAN WRITTEN BEFORE THIS MUST KEEP MEANING WHAT IT MEANT. Holds was a bare string, and every plan an
// operator has on disk uses one.
func TestABareStringStillNamesOneComponent(t *testing.T) {
	var h heldComponents
	if err := json.Unmarshal([]byte(`"edges"`), &h); err != nil {
		t.Fatalf("a bare string is no longer accepted: %v", err)
	}
	if !h.has("edges") || h.has("control-plane") {
		t.Fatalf(`"edges" parsed to %v`, h)
	}
	// And it is written back as it arrived, so reading and writing a plan does not rewrite the operator's file.
	out, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `"edges"` {
		t.Errorf("a single component was written back as %s, not as the string the operator wrote", out)
	}
	both := heldComponents{"control-plane", "edges"}
	if out, _ := json.Marshal(both); string(out) != `["control-plane","edges"]` {
		t.Errorf("two components were written back as %s", out)
	}
}

// ★ AND WHAT IS NOT A COMPONENT IS STILL REFUSED, with the name of the thing that was not understood. A list
// that accepts anything is how "store" or a typo becomes a machine that quietly runs nothing.
func TestAnUnknownComponentIsNamedInTheRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{"deployment":"example.test","regions":[{"id":"a","founding":true,"holds_state":true,
	  "machines":[{"name":"n","holds":["control-plane","edgez"],"addresses":["10.0.0.1","10.0.0.2"]}]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Refused by whichever of the two looks first — LoadPlan validates as it reads. What matters is that it
	// is refused and that the refusal names the word nobody understood.
	p, err := LoadPlan(path)
	if err == nil {
		err = p.Validate()
	}
	if err == nil {
		t.Fatal("a machine holding \"edgez\" was accepted")
	}
	if !strings.Contains(err.Error(), "edgez") {
		t.Errorf("the refusal does not name what was not understood: %v", err)
	}
}

// ★★★ A MACHINE THAT SAYS IT HOLDS BOTH MUST RENDER BOTH (2026-08-31, found by standing the lab up and
// reading the file the installer wrote).
//
// holds became a list so one machine could hold the control plane and the Edges. The function that turns a
// plan into a machine's shape still answered the old question — a machine holding the control plane was
// given edges:false — so the smallest redundant deployment rendered its control plane, its stores, and its
// DOORWAY, with no Edge process behind it. The door was there; the fleet was not.
//
// And whether the store spans regions is the plan's to know: the printed order did not pass the flag, so the
// founding machine rendered three members in one place while its own environment named one. The environment
// and the file it configures disagreed, and nothing said so.
func TestAMachineHoldingBothRendersBoth(t *testing.T) {
	p := planOfThree(t)
	for _, r := range p.Regions {
		shape := p.shapeOf(r, r.Machines[0])
		if !shape.runsEdges() {
			t.Errorf("%s: the machine holds %v and renders no Edge process — its region would have a doorway "+
				"with nothing behind it", r.ID, r.Machines[0].Holds)
		}
		if !shape.holdsAControlPlane() {
			t.Errorf("%s: the machine holds %v and renders no control plane", r.ID, r.Machines[0].Holds)
		}
		if !shape.storeSpansRegions {
			t.Errorf("%s: three regions hold state and this machine still renders the whole store — three "+
				"votes in one place, and losing that place loses the quorum", r.ID)
		}
	}
}

// ★ AND A DEPLOYMENT WITH ONE STATE-BEARING REGION STILL RENDERS THE WHOLE STORE, because on one host three
// members survive a container restart and are lost with the host either way.
func TestOneStateBearingRegionKeepsTheWholeStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{"deployment":"example.test","regions":[
	 {"id":"only","founding":true,"holds_state":true,"machines":[
	  {"name":"n","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"]}]}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	shape := p.shapeOf(p.Regions[0], p.Regions[0].Machines[0])
	if shape.storeSpansRegions {
		t.Error("a deployment with one state-bearing region was told its store spans regions")
	}
	if !shape.runsEdges() {
		t.Error("the one machine renders no Edge process")
	}
}
