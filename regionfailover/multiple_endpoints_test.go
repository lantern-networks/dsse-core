package regionfailover

import "testing"

func TestThreeDoorsInOneRegionRetainedAndFailOverByDoor(t *testing.T) {
	a := RegionEndpoint{Region: "kiri", Endpoint: "https://agents.node-a.example"}
	b := RegionEndpoint{Region: "kiri", Endpoint: "https://agents.node-b.example"}
	c := RegionEndpoint{Region: "kiri", Endpoint: "https://agents.node-c.example"}
	s := New([]RegionEndpoint{a, b, c, a}, "kiri")
	if len(s.allowed) != 3 {
		t.Fatalf("normalized doors=%v", s.allowed)
	}
	s.SetUnhealthyStrikes(2) // same hysteresis as region changes: transient door loss must not flap a mux
	probe := func(health map[string]Health) Probe {
		return func(ep RegionEndpoint) Health { return health[ep.Endpoint] }
	}
	all := map[string]Health{a.Endpoint: up(1), b.Endpoint: up(2), c.Endpoint: up(3)}
	if d := s.Evaluate(probe(all)); d.Current != a || len(d.FailoverSet) != 2 {
		t.Fatalf("initial=%+v", d)
	}
	all[a.Endpoint] = down()
	if d := s.Evaluate(probe(all)); !d.Held || d.Current != a {
		t.Fatalf("first strike=%+v", d)
	}
	if d := s.Evaluate(probe(all)); d.Current != b || d.Current.Region != "kiri" {
		t.Fatalf("failover=%+v", d)
	}
	all[a.Endpoint] = up(1)
	if d := s.Evaluate(probe(all)); d.Current != b {
		t.Fatalf("running failback=%+v", d)
	}
	s.UpdateList([]RegionEndpoint{a, c}, "kiri")
	if s.Current() != "" {
		t.Fatal("removed door remained current")
	}
	all[a.Endpoint], all[c.Endpoint] = down(), down()
	if d := s.Evaluate(probe(all)); d.State != StateFailClosed {
		t.Fatalf("all allowed doors down=%+v", d)
	}
}

func TestAdmissionDenyDoesNotShopOtherDoor(t *testing.T) {
	a := RegionEndpoint{Region: "kiri", Endpoint: "https://agents.node-a.example"}
	b := RegionEndpoint{Region: "kiri", Endpoint: "https://agents.node-b.example"}
	s := New([]RegionEndpoint{a, b}, "kiri")
	s.SetDenyOnAdmissionDeny(true)
	s.SetInstantRevokeOnAdmissionDeny(true)
	d := s.Evaluate(func(ep RegionEndpoint) Health {
		if ep == a {
			return deniedAdmit()
		}
		return up(1)
	})
	if d.State != StateDenied {
		t.Fatalf("deny must not shop another door: %+v", d)
	}
}
