package regionfailover

import "testing"

// ★ Restart is the fail-back event, and that is a DECISION rather than an accident — see Selector.current.
//
// Without it, one transient blip on the preferred region moves a device permanently: the selector keeps a
// healthy current region regardless of priority, so over time a fleet drifts onto whichever regions happened to
// be up during past blips and never returns, with every device reporting healthy the whole way. The operator's
// configured preference quietly stops meaning anything.
//
// With it, and with nothing persisting the choice, the fleet re-homes as machines restart — spread by reboots,
// updates and sleep/wake instead of by a stagger mechanism nobody has to maintain.
func TestRestartIsTheFailBackEvent(t *testing.T) {
	p1 := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 1}
	p2 := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 2}
	outage := probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": up(10)})
	recovered := probeFrom(map[string]Health{"jp-tokyo": up(5), "jp-osaka": up(10)})

	run := New([]RegionEndpoint{p1, p2}, "")
	run.SetUnhealthyStrikes(1)
	run.Evaluate(outage)
	if d := run.Evaluate(outage); d.Current.Region != "jp-osaka" {
		t.Fatalf("failover: expected jp-osaka while the priority-1 region is down, got %s", d.Current.Region)
	}

	// The preferred region comes back and stays back. The RUNNING agent deliberately does not return: a whole
	// fleet moving in the same probe round is a reconnect storm aimed at the one region that just recovered.
	var last Decision
	for i := 0; i < 50; i++ {
		last = run.Evaluate(recovered)
	}
	if last.Current.Region != "jp-osaka" {
		t.Fatalf("a running agent must NOT fail back on its own (herd avoidance); it moved to %s.\n"+
			"If in-run fail-back was added deliberately — with a stability hold-down, a per-device stagger and "+
			"a back-off on repeated returns — change this test on purpose, and say so.", last.Current.Region)
	}
	// ...but it is offered as the next hop, so the state is visible rather than forgotten.
	if len(last.FailoverSet) == 0 || last.FailoverSet[0].Region != "jp-tokyo" {
		t.Fatalf("the recovered higher-priority region must at least appear as the preferred alternative, got %+v", last.FailoverSet)
	}

	// RESTART: a fresh Selector, same configuration, same world.
	restarted := New([]RegionEndpoint{p1, p2}, "")
	if d := restarted.Evaluate(recovered); d.Current.Region != "jp-tokyo" {
		t.Fatalf("restart must re-home on the highest-priority healthy region, got %s — this is the ONLY "+
			"fail-back path, so if it stops working the fleet never returns", d.Current.Region)
	}
}

// The property the fail-back rests on, asserted directly: a new Selector remembers nothing. Written separately
// from the test above because "remember the last region across restarts" is an obvious-looking optimisation,
// and the thing it silently removes is the only mechanism that brings a fleet home.
func TestANewSelectorRemembersNoRegion(t *testing.T) {
	s := New([]RegionEndpoint{{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 2}}, "")
	if s.current != "" {
		t.Fatalf("a fresh Selector must start with no current region, got %q — a persisted choice disables "+
			"the restart fail-back for every device that has one", s.current)
	}
}

// Restarting DURING an outage must land on the best AVAILABLE region, not refuse to start because the
// preferred one is down. Priority is preference; it is never reachability.
func TestRestartDuringAnOutageTakesTheNextPriority(t *testing.T) {
	p1 := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 1}
	p2 := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 2}
	s := New([]RegionEndpoint{p1, p2}, "")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": up(10)}))
	if d.State != StateConnected || d.Current.Region != "jp-osaka" {
		t.Fatalf("a restart while the preferred region is down must connect to the next priority, got %s/%s", d.State, d.Current.Region)
	}
}
