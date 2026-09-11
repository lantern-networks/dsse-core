package agentrollout

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreAndDecision(t *testing.T) {
	s := NewAgentRolloutStore()
	if s.Get("acme").IsSet() {
		t.Fatal("an unset tenant should have no plan")
	}
	s.Set("acme", AgentRolloutPlan{DesiredVersion: "2.0.0", Intent: "rollout"})
	if got := s.Get("acme"); !got.IsSet() || got.DesiredVersion != "2.0.0" {
		t.Fatalf("plan should round-trip: %+v", got)
	}

	// rollout: a device behind the target must update
	if target, _, req := AgentRolloutDecision(AgentRolloutPlan{DesiredVersion: "2.0.0", Intent: "rollout"}, "1.0.0", "1.5.0", "stable"); target != "2.0.0" || !req {
		t.Fatalf("rollout should require update to 2.0.0, got target=%s req=%v", target, req)
	}
	// freeze: no device may move
	if _, _, req := AgentRolloutDecision(AgentRolloutPlan{Frozen: true}, "1.0.0", "1.5.0", "stable"); req {
		t.Fatal("a freeze must halt updates")
	}
	// no plan: fall back to the static target
	if target, _, _ := AgentRolloutDecision(AgentRolloutPlan{}, "1.0.0", "1.5.0", "stable"); target != "1.5.0" {
		t.Fatalf("no plan should fall back to 1.5.0, got %s", target)
	}
}

// ★ THE HALT MUST SURVIVE THE CONTROL PLANE'S OWN RESTART (2026-08-11, second review). Edges pull this store
// as the authority. While it was entirely in memory, the first successful fetch after a CP restart returned an
// EMPTY plan and every Edge holding an incident freeze replaced it with "not halted" — a process restart
// un-withdrawing a bad release, which is the one thing a freeze exists to make impossible.
func TestAHaltSurvivesTheControlPlaneRestarting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_rollout.json")

	before := NewAgentRolloutStore()
	if err := before.LoadFrom(path); err != nil {
		t.Fatalf("load (absent is not an error): %v", err)
	}
	if err := before.Set("tenant-a", AgentRolloutPlan{Frozen: true, Reason: "0.2.6 bricked the pilot ring"}); err != nil {
		t.Fatalf("set: %v", err)
	}

	// A new process, as after a restart.
	after := NewAgentRolloutStore()
	if err := after.LoadFrom(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := after.Get("tenant-a")
	if !got.Frozen || got.Reason == "" {
		t.Fatalf("the halt did not survive the restart: %+v", got)
	}
}

// A store that cannot be read must not answer "no halt": the caller stops instead.
func TestAnUnreadableStoreIsAnErrorRatherThanAnEmptyOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_rollout.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewAgentRolloutStore().LoadFrom(path); err == nil {
		t.Fatal("a corrupt halt store must be an error, not an empty set of plans")
	}
}

// ★ A HALT MUST BE LIFTABLE (2026-08-11, found while tidying the lab after an end-to-end verification — the
// tidy-up is what exposed it). Frozen was derived as `intent == freeze` and the request's own field was
// ignored, so the only route back was intent=rollout, whose desired_version nothing consumes. Once that intent
// was refused as unimplemented, the freeze became permanent: a control an operator can apply and never remove
// is not a control.
func TestAFreezeCanBeLiftedAndBothDirectionsNeedAReason(t *testing.T) {
	no := false
	yes := true

	halted, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{
		Intent: AgentRolloutIntentFreeze, Frozen: &yes, Reason: "0.2.6 bricked the pilot ring"})
	if err != nil || !halted.Frozen {
		t.Fatalf("a halt must halt: %+v (%v)", halted, err)
	}
	// Unstated still halts: that is what somebody reaching for this in an incident means.
	implied, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{
		Intent: AgentRolloutIntentFreeze, Reason: "halting"})
	if err != nil || !implied.Frozen {
		t.Fatalf("an unstated freeze must halt: %+v (%v)", implied, err)
	}

	released, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{
		Intent: AgentRolloutIntentFreeze, Frozen: &no, Reason: "0.2.7 published and verified on the pilot ring"})
	if err != nil {
		t.Fatalf("releasing: %v", err)
	}
	if released.Frozen {
		t.Fatal("★ a stated false must RELEASE the fleet; the halt was permanent while this was ignored")
	}

	// Both directions are decisions somebody explains later, and "why did this start moving again" is the
	// harder question of the two.
	if _, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{
		Intent: AgentRolloutIntentFreeze, Frozen: &no}); err == nil {
		t.Error("releasing a fleet without a reason must be refused")
	}
	if _, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{
		Intent: AgentRolloutIntentFreeze, Frozen: &yes}); err == nil {
		t.Error("halting a fleet without a reason must be refused")
	}
}

// ★ A PLAN THAT COULD NOT BE WRITTEN MUST NOT BE VISIBLE (third review). Edges pull this store; publishing
// before the bytes are down meant an operator told "not accepted" (500) had their halt applied anyway — and,
// worse for an unfreeze, told it failed while every device resumed.
func TestAPlanThatFailsToPersistIsNotPublished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent_rollout.json")
	s := NewAgentRolloutStore()
	if err := s.LoadFrom(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("tenant-a", AgentRolloutPlan{Frozen: true, Reason: "halted"}); err != nil {
		t.Fatalf("first set: %v", err)
	}

	// Make the write fail: the parent becomes unwritable, so the temp file cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	// ★ AND CHECK THAT IT WORKED. On Windows os.Chmod SUCCEEDS on a directory and changes nothing about who
	// may create files in it, so the Skipf above never fires and the assertion below fails on a host where
	// nothing is wrong — it blocked every push from win-dev-1, the same way the 0600 mode assertion in
	// sentinels did. Probing the CAPABILITY rather than testing runtime.GOOS, so a host that gains or loses
	// it needs no edit to a platform list.
	probe := filepath.Join(dir, ".write-probe")
	if f, perr := os.Create(probe); perr == nil {
		f.Close()
		os.Remove(probe)
		t.Skipf("SKIP: this host does not enforce directory write permission (chmod 0500 left %s writable), so "+
			"the publish-after-persist rule cannot be exercised here. It is asserted in full wherever Unix modes "+
			"are honoured, and that is where this test's guarantee comes from", dir)
	}

	if err := s.Set("tenant-a", AgentRolloutPlan{Frozen: false, Reason: "released"}); err == nil {
		t.Fatal("a store that cannot be written must report it")
	}
	if got := s.Get("tenant-a"); !got.Frozen {
		t.Fatal("★ the unfreeze became visible to edges while the API reported failure")
	}
}

// ★★★ THE CONTROL WAS ONE-WAY (2026-08-28, measured by pressing it). rollout and rollback each REQUIRE a
// version — correctly, you cannot advance to nothing — so an organization that had named one had no way back:
// every path through this endpoint was refused, and the only fleet a customer could not release was the one
// they had held themselves.
func TestAnOrganizationCanGoBackToFollowingWhatIsOffered(t *testing.T) {
	s := NewAgentRolloutStore()
	now := time.Now().UTC()
	if _, err := s.Apply("tenant_a", AgentRolloutPlan{Intent: AgentRolloutIntentRollout, DesiredVersion: "0.2.9"}, now); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if got := s.Get("tenant_a").DesiredVersion; got != "0.2.9" {
		t.Fatalf("pin did not take: %q", got)
	}
	if _, err := ValidateAgentRolloutUpdate(AgentRolloutUpdateRequest{Intent: AgentRolloutIntentFollow}); err != nil {
		t.Fatalf("following what the deployment offers was refused: %v", err)
	}
	if _, err := s.Apply("tenant_a", AgentRolloutPlan{Intent: AgentRolloutIntentFollow}, now); err != nil {
		t.Fatalf("follow: %v", err)
	}
	if got := s.Get("tenant_a").DesiredVersion; got != "" {
		t.Fatalf("the organization is still held on %q — it can pin and never un-pin", got)
	}

	// ★ AND IT MUST NOT RELEASE A FLEET SOMEBODY HALTED. Following is a statement about WHICH version.
	if _, err := s.Apply("tenant_b", AgentRolloutPlan{Intent: AgentRolloutIntentFreeze, Frozen: true,
		Reason: "0.3.0 bricked the pilot ring"}, now); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if _, err := s.Apply("tenant_b", AgentRolloutPlan{Intent: AgentRolloutIntentFollow}, now); err != nil {
		t.Fatalf("follow: %v", err)
	}
	if after := s.Get("tenant_b"); !after.Frozen {
		t.Fatal("choosing to follow released a fleet somebody halted — a form about WHICH version must not " +
			"be a way to lift a freeze")
	}
}
