package main

import (
	"strings"
	"testing"
)

// plan_order_test.go — that the ORDER is complete and correct, whatever the topology.
//
// ★★★ THE GOAL THIS SERVES, IN THE OPERATOR'S WORDS: for various topologies, with nobody helping during the
// install, given the prior information and the correct order, every component starts and works. Two of those
// three are already derived — the prior information is the plan, and the machines come from it. The order was
// nowhere: it was learned by doing it wrong, on real machines, and written down in no file.
//
// A property that only holds for the shape somebody happened to build is not a property, so these run against
// one region, two and three.

func orderOf(t *testing.T, p *Plan) []PlanStep {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("plan: %v", err)
	}
	return p.InstallOrder("/opt/dsse/region-a", "plan.json")
}

func stepIndex(steps []PlanStep, match func(PlanStep) bool) int {
	for i, s := range steps {
		if match(s) {
			return i
		}
	}
	return -1
}

// ★★★ EVERY MACHINE IS IN THE ORDER, EXACTLY ONCE. A machine nobody is told to start is a machine that is not
// there, on a deployment whose every screen is green.
func TestEveryMachineOfEveryTopologyIsInTheOrder(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		for _, m := range p.MachineNames() {
			// ★ A RESTART IS NOT A START. The founding control plane is started once and then recreated to
			// close the break-glass credential; counting both would report correct behaviour as a fault.
			starts := 0
			for _, s := range steps {
				if s.Machine == m && strings.Contains(s.Do, "up -d") && !strings.Contains(s.Do, "force-recreate") {
					starts++
				}
			}
			if starts == 0 {
				t.Errorf("%s: nothing tells anyone to start %s", name, m)
			}
			if starts > 1 {
				t.Errorf("%s: %s is started %d times", name, m, starts)
			}
		}
	}
}

// ★★★ NOTHING PRECEDES THE MINT. A deployment has ONE anchor; a machine started before it exists has nothing
// to be part of, and a second mint gives a device that MOVES an issuer it has never heard of.
func TestTheDeploymentIsMintedFirst(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		if !strings.Contains(steps[0].Do, "-plan") || strings.Contains(steps[0].Do, "-carry") {
			t.Errorf("%s: the first step is not the mint: %s", name, steps[0].Do)
		}
		if steps[0].Machine != p.foundingRegion().controlPlane().Name {
			t.Errorf("%s: the deployment is minted on %s rather than the founding control plane", name, steps[0].Machine)
		}
	}
}

// ★★★ THE ADMINISTRATOR IS CREATED BEFORE ANY OTHER MACHINE IS PACKED. The marker and the fleet credential it
// writes go into the directory every later machine is packed FROM — so a machine packed before it is born
// answering 401 to its own control plane, on a deployment that is otherwise correct. It reads as a broken new
// region and it is a stale source.
func TestNoMachineIsPackedBeforeTheAdministratorExists(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		bootstrap := stepIndex(steps, func(s PlanStep) bool { return strings.Contains(s.Do, "-bootstrap-admin") })
		if bootstrap < 0 {
			t.Fatalf("%s: nothing creates this deployment's first administrator", name)
		}
		firstCarry := stepIndex(steps, func(s PlanStep) bool { return strings.Contains(s.Do, "-carry") })
		if firstCarry >= 0 && firstCarry < bootstrap {
			t.Errorf("%s: a machine is packed at step %d, before the administrator exists at step %d",
				name, firstCarry+1, bootstrap+1)
		}
	}
}

// ★★★ THE BREAK-GLASS CREDENTIAL IS CLOSED BEFORE THE DEPLOYMENT IS HANDED OVER. Creating the administrator
// writes the marker, but the process running NOW still has a credential armed that authorises as owner and
// attributes every act to nobody.
func TestTheBreakGlassCredentialIsClosedAfterTheAdministratorIsCreated(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		bootstrap := stepIndex(steps, func(s PlanStep) bool { return strings.Contains(s.Do, "-bootstrap-admin") })
		restart := stepIndex(steps, func(s PlanStep) bool {
			return strings.Contains(s.Do, "force-recreate") && strings.Contains(s.Do, "control-plane")
		})
		if restart < 0 || restart < bootstrap {
			t.Errorf("%s: nothing restarts the control planes after the administrator is created, so the "+
				"break-glass credential stays armed in the running process", name)
		}
	}
}

// ★★★ A REGION THAT JOINS COMES UP AFTER THE ONE IT JOINS. It takes the deployment's ONE consensus store;
// started before that answers, its database members elect among themselves and the deployment has two
// opinions about which database is primary.
func TestAJoiningRegionStartsAfterTheFoundingOne(t *testing.T) {
	for name, p := range shapes() {
		if len(p.Regions) < 2 {
			continue
		}
		steps := orderOf(t, p)
		foundingUp := stepIndex(steps, func(s PlanStep) bool {
			return s.Machine == p.foundingRegion().controlPlane().Name && strings.Contains(s.Do, "up -d")
		})
		for _, r := range p.Regions {
			if r.Founding {
				continue
			}
			for _, m := range r.Machines {
				at := stepIndex(steps, func(s PlanStep) bool {
					return s.Machine == m.Name && strings.Contains(s.Do, "up -d")
				})
				if at < 0 || at < foundingUp {
					t.Errorf("%s: %s of %s starts before the founding region is running", name, m.Name, r.ID)
				}
			}
		}
	}
}

// ★★★ WITHIN A REGION, ITS CONTROL PLANE COMES UP BEFORE ITS EDGES. An Edge takes its configuration and its
// organizations' material from the control plane of its own region; started first it comes up serving
// nothing and says so only in its own log.
func TestAnEdgeStartsAfterTheControlPlaneOfItsOwnRegion(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		for _, r := range p.Regions {
			cpAt := stepIndex(steps, func(s PlanStep) bool {
				return s.Machine == r.controlPlane().Name && strings.Contains(s.Do, "up -d")
			})
			for _, m := range r.Machines {
				if m.Holds.has("control-plane") {
					continue
				}
				at := stepIndex(steps, func(s PlanStep) bool {
					return s.Machine == m.Name && strings.Contains(s.Do, "up -d")
				})
				if at < 0 || at < cpAt {
					t.Errorf("%s: %s starts before %s's control plane", name, m.Name, r.ID)
				}
			}
		}
	}
}

// ★★★ EVERY STEP SAYS WHAT MUST ALREADY BE TRUE, AND WHAT GOES WRONG OTHERWISE. This is the whole difference
// between an order and a list: an operator with nobody helping needs to be able to check the precondition
// before acting, and to recognise the failure if they did not.
func TestEveryStepSaysWhatItNeedsAndWhatBreaks(t *testing.T) {
	for name, p := range shapes() {
		for i, s := range orderOf(t, p) {
			if strings.TrimSpace(s.Needs) == "" {
				t.Errorf("%s: step %d says nothing about what must already be true: %s", name, i+1, s.Do)
			}
			if len(strings.Fields(s.Why)) < 8 {
				t.Errorf("%s: step %d does not say what goes wrong if it is done out of order: %q", name, i+1, s.Why)
			}
			if strings.TrimSpace(s.Machine) == "" {
				t.Errorf("%s: step %d does not say where it runs", name, i+1)
			}
		}
	}
}

// ★★★ NO STEP NEEDS A VALUE THAT IS NOT IN THE PLAN. This is what "given the prior information" means: if a
// command carries a placeholder for something the description could have supplied, then somebody has to be
// there to supply it, and that somebody is the person this order exists to do without.
func TestNoStepNeedsAValueTheDescriptionDoesNotHave(t *testing.T) {
	// The three a plan deliberately does NOT hold: who the administrator is, what they are called, and the
	// token minted at bootstrap. Those are answers about PEOPLE and secrets, not about the deployment.
	allowed := map[string]bool{"<address>": true, "<name>": true, "<token>": true}
	for name, p := range shapes() {
		for i, s := range orderOf(t, p) {
			for _, word := range strings.Fields(s.Do) {
				if !strings.HasPrefix(word, "<") || allowed[word] {
					continue
				}
				t.Errorf("%s: step %d asks for %s, which the description could have supplied: %s",
					name, i+1, word, s.Do)
			}
		}
	}
}

// ★★★ THE LAST STEP MEASURES THE FLEET, at addresses this deployment actually offers. Half of what -verify
// asks is about the fleet rather than a node, and a deployment answering those from one node looks complete
// and is not.
func TestTheOrderEndsByMeasuringTheWholeFleet(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		last := steps[len(steps)-1]
		if !strings.Contains(last.Do, "-verify") {
			t.Errorf("%s: the order does not end by verifying: %s", name, last.Do)
		}
		for _, r := range p.Regions {
			// ★ AT THE ADDRESS REACHABLE FROM WHERE THE CHECK RUNS — its own inside the founding region, the
			// one it publishes to the others everywhere else.
			if !strings.Contains(last.Do, p.fromFounding(r.controlPlane(), r, 0)) {
				t.Errorf("%s: the final check does not reach %s's control plane, so the fleet questions are "+
					"answered without it", name, r.ID)
			}
		}
		// ★ AND ON 443. Per-node ports published behind the door are the substitution a one-host lab makes;
		// answers gathered there are true of the nodes and are not evidence about the deployment.
		for _, word := range strings.Fields(last.Do) {
			if !strings.HasPrefix(word, "https://") {
				continue
			}
			for _, target := range strings.Split(word, ",") {
				if strings.Contains(target, "@") {
					continue // NAME@ADDRESS: 443 by construction
				}
				if strings.Count(target, ":") > 1 {
					t.Errorf("%s: the final check asks %s, which is not 443", name, target)
				}
			}
		}
	}
}

// ★★★ THE FINAL CHECK REACHES EVERY MACHINE FROM WHERE IT RUNS (2026-08-28, measured). It runs on the
// founding control plane and was given each machine's OWN address — which for another region is a private one,
// routable from nowhere but there. The check that measures the FLEET could reach only half of it, on a
// deployment where every machine was answering.
func TestTheFinalCheckUsesAddressesReachableFromWhereItRuns(t *testing.T) {
	for name, p := range shapes() {
		steps := orderOf(t, p)
		last := steps[len(steps)-1]
		for _, r := range p.Regions {
			if r.Founding {
				continue
			}
			for _, m := range r.Machines {
				for _, own := range m.Addresses {
					if strings.Contains(last.Do, "@"+own) {
						t.Errorf("%s: the final check reaches %s at %s, which is private to %s and routable "+
							"from nowhere else", name, m.Name, own, r.ID)
					}
				}
				if !strings.Contains(last.Do, "@"+m.reachableAt()) {
					t.Errorf("%s: the final check does not reach %s at the address the other regions use (%s)",
						name, m.Name, m.reachableAt())
				}
			}
		}
	}
}
