package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/updateplatform"
)

// ★ The three outcomes that must not collapse. A single "did not update" would make a forged manifest, a
// device whose pass could not run at all, and a device with nothing published indistinguishable — and only
// one of them is the normal state.
func TestTheThreeFailuresAreDistinguishable(t *testing.T) {
	rejected := Classify(updateplatform.TickResult{}, fmt.Errorf("%w: signature is not from a trusted key", updateplatform.ErrManifestRejected), "the lab source")
	fault := Classify(updateplatform.TickResult{}, errors.New("permission denied"), "the lab source")
	nothing := Classify(updateplatform.TickResult{}, updateplatform.ErrNoManifest, "the lab source")

	if rejected.Action == fault.Action || rejected.Action == nothing.Action || fault.Action == nothing.Action {
		t.Fatalf("collapsed: rejected=%s fault=%s nothing=%s", rejected.Action, fault.Action, nothing.Action)
	}
	if !rejected.Reportable {
		t.Fatal("a refused manifest must always reach the event log")
	}
	if !fault.Reportable {
		t.Error("a pass that attempted nothing must say so; a quiet device and a stuck one are not the same")
	}
	if nothing.Reportable {
		t.Error("nothing published is the majority state and must be silent")
	}
	if !strings.Contains(rejected.Reason, "the lab source") {
		t.Errorf("the refusal must name where the manifest came from, got %q", rejected.Reason)
	}
}

// Anything else that stopped a pass — an unreadable journal, a record that could not be kept — means nothing
// was attempted, and that has to be loud rather than looking like a quiet device.
func TestAnythingThatStopsAPassIsReportedAsBlocked(t *testing.T) {
	r := Classify(updateplatform.TickResult{}, errors.New("journal is unreadable"), "src")
	if r.Action != ActionBlocked || !r.Reportable {
		t.Fatalf("action=%s reportable=%t, want blocked+reportable", r.Action, r.Reportable)
	}
}

// Waiting is the designed steady state of a device inside a rollout. A fleet of them must not page anyone.
func TestWaitingIsNotAnEvent(t *testing.T) {
	r := Classify(updateplatform.TickResult{
		Outcome: agentupdate.Outcome{Action: agentupdate.ActionWaiting, Reason: "outside the maintenance window"},
	}, nil, "src")
	if r.Reportable {
		t.Fatal("waiting raised an event")
	}
}

func TestHandingADeviceToAnInstallerIsAnEvent(t *testing.T) {
	r := Classify(updateplatform.TickResult{
		Outcome: agentupdate.Outcome{Action: agentupdate.ActionExecuting, Reason: "handed 0.2.0 to the installer"},
	}, nil, "src")
	if !r.Reportable {
		t.Fatal("an install starting must be recorded")
	}
}

// ★ A closed-out attempt is the only moment a completed update is knowable — the installer replaced the
// process that started it — so it is reportable even when the pass then finds nothing else to do.
func TestAReconciledAttemptIsReportedEvenOnAnOtherwiseQuietPass(t *testing.T) {
	r := Classify(updateplatform.TickResult{
		Reconciled: true,
		Notes:      []string{"attempt at 0.2.0 completed: this device is now running it"},
		Outcome:    agentupdate.Outcome{Action: agentupdate.ActionNone, Reason: "no manifest published for this device"},
	}, nil, "src")
	if !r.Reportable {
		t.Fatal("a completed update was not recorded anywhere; nothing else will ever say it happened")
	}
	if !strings.Contains(r.Reason, "completed") {
		t.Fatalf("the reason must carry what was reconciled, got %q", r.Reason)
	}
}

// --- the rollout plan, and the rule the freeze rests on -------------------------------------------------------

func signPlan(t *testing.T, p agentupdate.RolloutPlan) (path string, pubkey string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatal(err)
	}
	// SignTyped: the plan has its own envelope type so it cannot be confused with the exclusion policy the same
	// key signs. A test that signed it untyped would be testing a document the Edge no longer produces.
	env, err := sg.SignTyped(agentupdate.RolloutPlanEnvelopeType, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	path = filepath.Join(t.TempDir(), "update-plan.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, sg.PublicKeyHex()
}

func freshPlan() agentupdate.RolloutPlan {
	return agentupdate.RolloutPlan{
		SchemaVersion: agentupdate.RolloutPlanSchema,
		Frozen:        true,
		FrozenReason:  "0.2.0 bricked the pilot ring",
		EligibleSince: "2026-08-15T02:00:00Z",
		// A plan may only authorise a wave for the release it was computed for, and only while it is fresh.
		// Both are stated here because a plan without them can still HALT a device and can no longer START one.
		TargetVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Window:        &agentupdate.PlanWindow{LocalStart: "23:00", LocalEnd: "05:00", RequireUnattended: true, DeadlineDays: 7},
	}
}

func TestAVerifiedPlanCarriesTheFreezeAndTheWave(t *testing.T) {
	path, key := signPlan(t, freshPlan())
	r, err := agentupdate.LoadRollout(path, []string{key}, time.Now(),
		agentupdate.RolloutExpectation{Version: "0.2.0", MaxAge: agentupdate.DefaultPlanMaxAge})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.Frozen || r.FrozenReason == "" {
		t.Fatalf("the freeze did not survive: %+v", r)
	}
	if r.EligibleSince.IsZero() {
		t.Fatal("the wave start did not survive")
	}
	if !strings.Contains(r.Source, "verified") {
		t.Fatalf("source = %q, want it to say the plan was verified", r.Source)
	}
}

// ★ THE RULE THE WHOLE WITHDRAWAL MECHANISM RESTS ON. A plan that exists and cannot be verified is a FREEZE,
// never a fallback to the default. If damaging the file lifted the halt, the cheapest attack on the safety
// control would be to break it — and the commonest accident would have the same effect.
func TestADamagedPlanFreezesInsteadOfFallingBackToTheDefault(t *testing.T) {
	good := freshPlan()
	good.Frozen = false // so a fallback-to-default would be indistinguishable from success
	path, key := signPlan(t, good)

	for name, mutate := range map[string]func(string){
		"signed by another key": func(p string) {
			other, _ := signPlan(t, good)
			b, _ := os.ReadFile(other)
			os.WriteFile(p, b, 0o600)
		},
		"truncated": func(p string) { os.WriteFile(p, []byte(`{"type":"x"`), 0o600) },
		"emptied":   func(p string) { os.WriteFile(p, nil, 0o600) },
		"not an envelope": func(p string) {
			os.WriteFile(p, []byte(`{"frozen":false,"local_start":"00:00"}`), 0o600)
		},
		"payload replaced": func(p string) {
			var env map[string]any
			b, _ := os.ReadFile(p)
			json.Unmarshal(b, &env)
			env["payload_b64"] = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"dsse.agent-update-plan.v1","frozen":false}`))
			nb, _ := json.Marshal(env)
			os.WriteFile(p, nb, 0o600)
		},
	} {
		p := filepath.Join(t.TempDir(), "update-plan.json")
		b, _ := os.ReadFile(path)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		mutate(p)

		r, err := agentupdate.LoadRollout(p, []string{key}, time.Now(), agentupdate.RolloutExpectation{})
		if !errors.Is(err, agentupdate.ErrPlanUnverifiable) {
			t.Errorf("%s: err = %v, want agentupdate.ErrPlanUnverifiable", name, err)
		}
		if !r.Frozen {
			t.Errorf("%s: a damaged plan did not freeze — damaging the plan must never be a way to lift a halt", name)
		}
		if r.FrozenReason == "" {
			t.Errorf("%s: frozen with no reason; an operator cannot act on that", name)
		}
	}
}

// An ABSENT plan is the ordinary un-provisioned device and must NOT freeze: a fleet that never configured this
// would otherwise be halted by the arrival of the feature.
func TestNoPlanIsNotAFreeze(t *testing.T) {
	r, err := agentupdate.LoadRollout(filepath.Join(t.TempDir(), "absent.json"), []string{"ab"}, time.Now(), agentupdate.RolloutExpectation{})
	if err != nil {
		t.Fatalf("an absent plan must not be an error: %v", err)
	}
	if r.Frozen {
		t.Fatal("an absent plan froze the device")
	}
}

// Opting out of verification is allowed and must never be silent: without a pin the halt is only as strong as
// the file's permissions, and a device that looks protected while it is not is the worse outcome.
func TestAnUnpinnedDeviceSaysItsPlanIsUnverified(t *testing.T) {
	path, _ := signPlan(t, freshPlan())
	r, err := agentupdate.LoadRollout(path, nil, time.Now(), agentupdate.RolloutExpectation{})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.Frozen {
		t.Fatal("the plan's freeze was dropped along with its verification")
	}
	if !strings.Contains(r.Source, "UNVERIFIED") {
		t.Fatalf("source = %q; an unpinned device must say so", r.Source)
	}
}

// ★ The type check, and the substitution it refuses: an exclusion policy signed by the SAME key. Without it
// the only thing standing between that document and a device's plan is the payload's schema field, which is a
// coincidence of which struct happened to decode rather than a statement about what was signed.
func TestASteerPolicySignedByTheSameKeyIsNotARolloutPlan(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatal(err)
	}
	// The plan payload byte-for-byte, under the steer-policy type. Nothing about decoding can refuse this one.
	env, err := sg.Sign(freshPlan(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	path := filepath.Join(t.TempDir(), "update-plan.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	r, lerr := agentupdate.LoadRollout(path, []string{sg.PublicKeyHex()}, time.Now(), agentupdate.RolloutExpectation{})
	if !errors.Is(lerr, agentupdate.ErrPlanUnverifiable) {
		t.Fatalf("err = %v, want agentupdate.ErrPlanUnverifiable", lerr)
	}
	if !r.Frozen {
		t.Fatal("a document of the wrong type did not freeze the device")
	}
}

// A plan that only halts must not rewrite the schedule of every device that reads it.
func TestAPlanWithoutAWindowLeavesTheLocalOneAlone(t *testing.T) {
	p := freshPlan()
	p.Window = nil
	path, key := signPlan(t, p)
	r, err := agentupdate.LoadRollout(path, []string{key}, time.Now(), agentupdate.RolloutExpectation{})
	if err != nil {
		t.Fatal(err)
	}
	local := DefaultPlan()
	got := local.Apply(r)
	if got.LocalStart != local.LocalStart || got.DeadlineDays != local.DeadlineDays {
		t.Fatalf("a windowless plan rewrote the local schedule: %+v", got)
	}
}

func TestAPlanWithAWindowReplacesTheLocalOne(t *testing.T) {
	path, key := signPlan(t, freshPlan())
	r, _ := agentupdate.LoadRollout(path, []string{key}, time.Now(), agentupdate.RolloutExpectation{})
	got := DefaultPlan().Apply(r)
	if got.LocalStart != "23:00" || got.DeadlineDays != 7 {
		t.Fatalf("the tenant's window was not applied: %+v", got)
	}
}

// --- what --status says about the manifest ---------------------------------------------------------------

// ★ The gap win-dev-1 found by running both commands on one unchanged state: --dry-run said "REFUSED an
// update manifest … unverified" and --status was silent about the identical box. The command an operator runs
// FIRST must not be the quiet one about the document everything else rests on.
func TestStatusSaysWhatIsWrongWithTheManifest(t *testing.T) {
	rejected := DescribeManifest(agentupdate.Manifest{},
		fmt.Errorf("%w: signature is not from a trusted key", updateplatform.ErrManifestRejected), "the file")
	if !strings.Contains(rejected, "REFUSED") {
		t.Fatalf("a refused manifest must be loud in --status, got %q", rejected)
	}
	if !strings.Contains(rejected, "now") && !strings.Contains(rejected, "tonight") {
		t.Errorf("the refusal must carry its urgency; --status is where it is read first: %q", rejected)
	}

	none := DescribeManifest(agentupdate.Manifest{}, updateplatform.ErrNoManifest, "the file")
	if strings.Contains(none, "REFUSED") {
		t.Fatalf("a device with nothing published must not look alarming: %q", none)
	}
	if none == rejected {
		t.Fatal("nothing published and a refused manifest read the same; they need opposite responses")
	}
}

// A device that is fine must say what it is holding: the version is the answer to "is this box behind".
func TestStatusNamesTheVersionOnOffer(t *testing.T) {
	got := DescribeManifest(statusManifest(), nil, "the file")
	for _, want := range []string{"verified", "0.2.0", "windows/amd64"} {
		if !strings.Contains(got, want) {
			t.Errorf("--status must carry %q, got %q", want, got)
		}
	}
}

// And an MDM-delivered one must say DSSE will not install it. Otherwise an operator sees a version offered,
// nothing happening, and reasonably suspects the updater.
func TestStatusSaysWhenDSSEWillNotInstallTheVersionItIsShowing(t *testing.T) {
	m := statusManifest()
	m.Delivery = agentupdate.DeliveryMDM
	got := DescribeManifest(m, nil, "the file")
	if !strings.Contains(got, "NOT install") {
		t.Fatalf("an MDM-delivered manifest must say DSSE is not the installer, got %q", got)
	}
}

// statusManifest is a verified manifest as --status would find one.
func statusManifest() agentupdate.Manifest {
	return agentupdate.Manifest{
		Version: "0.2.0", Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64,
		Delivery: agentupdate.DeliveryDSSE, NotAfter: "2026-09-09T00:00:00Z",
	}
}
