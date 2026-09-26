package agentrollout

import (
	"github.com/lantern-networks/dsse-core/agentupdate"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestVersionChangesPreserveHaltAcrossRestart(t *testing.T) {
	for _, intent := range []string{AgentRolloutIntentRollout, AgentRolloutIntentRollback, AgentRolloutIntentFollow} {
		t.Run(intent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plans.json")
			s := NewAgentRolloutStore()
			if err := s.LoadFrom(path); err != nil {
				t.Fatal(err)
			}
			prior := AgentRolloutPlan{DesiredVersion: "2.0.0", ReleaseChannel: "stable", Frozen: true, Reason: "incident hold", Waves: &WaveSchedule{Waves: []RolloutWave{{Group: "Pilot", Priority: 9}}}, Window: &agentupdate.PlanWindow{LocalStart: "01:00", LocalEnd: "05:00"}}
			if err := s.Set("own", prior); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("other", prior); err != nil {
				t.Fatal(err)
			}
			input, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{Intent: intent, DesiredVersion: "3.0.0"})
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Apply("own", input, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if !got.Frozen || got.Reason != prior.Reason || !reflect.DeepEqual(got.Waves, prior.Waves) || !reflect.DeepEqual(got.Window, prior.Window) {
				t.Fatalf("%s changed independent controls: %+v", intent, got)
			}
			if _, _, update := AgentRolloutDecision(got, "1.0.0", "3.0.0", "stable"); update {
				t.Fatal("halted fleet may update")
			}
			restored := NewAgentRolloutStore()
			if err := restored.LoadFrom(path); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.Get("own"), got) || !reflect.DeepEqual(restored.Get("other"), prior) {
				t.Fatal("restart changed plans")
			}
		})
	}
}
func TestHaltChangesKeepNamedVersion(t *testing.T) {
	s := NewAgentRolloutStore()
	prior := AgentRolloutPlan{DesiredVersion: "2.0.0", ReleaseChannel: "stable"}
	if err := s.Set("own", prior); err != nil {
		t.Fatal(err)
	}
	for _, frozen := range []bool{true, false} {
		in, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{Intent: "freeze", Frozen: &frozen, Reason: "explicit decision"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Apply("own", in, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got.Frozen != frozen || got.DesiredVersion != prior.DesiredVersion || got.ReleaseChannel != prior.ReleaseChannel {
			t.Fatalf("halt erased version %+v", got)
		}
	}
}
func TestConcurrentHaltAndVersionSelection(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := NewAgentRolloutStore()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, in := range []AgentRolloutPlan{{Intent: "freeze", Frozen: true, Reason: "incident"}, {Intent: "rollout", DesiredVersion: "2.0.0"}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := s.Apply("own", in, time.Now()); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
		p := s.Get("own")
		if !p.Frozen || p.DesiredVersion != "2.0.0" || p.Reason != "incident" {
			t.Fatalf("concurrent intent lost %+v", p)
		}
	}
}

func TestReleaseChannelIntentContractAcrossRestart(t *testing.T) {
	for _, tc := range []struct{ name, intent, channel, want string }{
		{"version-unrestricted", "rollout", "", ""}, {"version-channel", "rollout", "beta", "beta"},
		{"rollback-unrestricted", "rollback", "", ""}, {"follow", "follow", "", ""},
		{"schedule", "schedule", "", "stable"}, {"freeze", "freeze", "", "stable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plans.json")
			s := NewAgentRolloutStore()
			if err := s.LoadFrom(path); err != nil {
				t.Fatal(err)
			}
			before := AgentRolloutPlan{DesiredVersion: "2.0.0", ReleaseChannel: "stable", Frozen: true, Reason: "incident hold"}
			if err := s.Set("own", before); err != nil {
				t.Fatal(err)
			}
			if err := s.Set("other", before); err != nil {
				t.Fatal(err)
			}
			in := AgentRolloutPlan{Intent: tc.intent, DesiredVersion: "3.0.0", ReleaseChannel: tc.channel, Frozen: true, Reason: "incident hold"}
			if tc.intent == "freeze" {
				in.DesiredVersion = ""
			}
			got, err := s.Apply("own", in, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if got.ReleaseChannel != tc.want || !got.Frozen || got.Reason != before.Reason {
				t.Fatal("intent violated channel or hold contract")
			}
			restored := NewAgentRolloutStore()
			if err := restored.LoadFrom(path); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.Get("own"), got) || !reflect.DeepEqual(restored.Get("other"), before) {
				t.Fatal("restart or tenant isolation failed")
			}
		})
	}
}
