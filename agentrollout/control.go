package agentrollout

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"strconv"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// Agent lifecycle: an admin-managed rollout / rollback control-plane. The per-device rollout
// endpoint previously returned a single static process flag (agent-target-version) as the target — an
// operator could neither drive a rollout to a new version nor ROLL BACK a bad one at runtime. This adds a
// per-tenant desired rollout plan (rollout target / rollback target / incident freeze) that the runtime
// rollout endpoint consults, plus the admin API to set it (audited). The target/update-required logic is a
// pure function so it is unit-testable without the store or the HTTP layer.

const (
	AgentRolloutIntentRollout  = "rollout"  // advance the fleet to a new desired version
	AgentRolloutIntentRollback = "rollback" // converge the fleet back onto a known-good version
	AgentRolloutIntentFreeze   = "freeze"   // incident halt: stop requiring any device to move
	// AgentRolloutIntentSchedule changes ONLY the wave schedule and the maintenance window.
	//
	// ★ IT EXISTS BECAUSE EDITING THE SCHEDULE MEANT TOUCHING THE HALT (2026-08-12, fourth review). With
	// rollout/rollback refused as unimplemented, the only way to save waves or a window was to send
	// intent=freeze — which also decides whether the fleet is halted. Changing the pilot ring's start date
	// would have carried a freeze decision with it, and the dangerous direction is the accidental one: an
	// operator adjusting a maintenance window at 10:00 lifting an incident halt somebody set at 03:00.
	AgentRolloutIntentSchedule = "schedule"
	// AgentRolloutIntentFollow clears the version an organization named, so its devices take whatever the
	// deployment offers.
	//
	// ★★★ WITHOUT IT THE CONTROL WAS ONE-WAY (2026-08-28, measured by pressing it). rollout and rollback each
	// REQUIRE a version — correctly, you cannot advance to nothing — so an organization that had named one had
	// no way to stop: every path back through this endpoint was refused, and the only fleet a customer could
	// not release was the one they had held themselves. Following is a decision like any other and it now has
	// its own name, so the record says which was made rather than showing an empty field.
	AgentRolloutIntentFollow = "follow"
)

// AgentRolloutPlan is a tenant's admin-managed desired agent rollout state.
type AgentRolloutPlan struct {
	DesiredVersion string `json:"desired_version"` // version every device should converge to (rollout OR rollback target)
	ReleaseChannel string `json:"release_channel"`
	Frozen         bool   `json:"frozen"` // incident freeze: no device is required to move
	Intent         string `json:"intent"` // rollout | rollback | freeze (operator intent, for audit/clarity)
	Reason         string `json:"reason"`
	UpdatedAt      string `json:"updated_at"`

	// ★ THE SCHEDULE LIVES HERE TOO, NOT IN A FILE ON EACH EDGE (2026-08-11). The halt moved to the control
	// plane first because it is the urgent one; leaving the waves and the window behind meant a fleet still had
	// as many schedules as it had edges, and a screen reading one of them would say "applied" for all — the
	// per-edge authored-rules defect this codebase has already paid for once.
	//
	// Both are POINTERS so "the control plane did not say" stays distinguishable from "it said none": a plan
	// that only sets the halt must not silently rewrite everyone's maintenance window to midnight-to-midnight.
	Waves  *WaveSchedule           `json:"waves,omitempty"`
	Window *agentupdate.PlanWindow `json:"window,omitempty"`
}

func (p AgentRolloutPlan) IsSet() bool {
	return strings.TrimSpace(p.DesiredVersion) != "" || p.Frozen || strings.TrimSpace(p.Intent) != "" ||
		p.Waves != nil || p.Window != nil
}

// AgentRolloutDecision computes a device's effective rollout target + whether an update is required,
// honoring the admin plan and falling back to the static target when no plan is set. A freeze halts all
// movement (update_required=false) so a bad rollout can be stopped instantly without clearing the target.
func AgentRolloutDecision(plan AgentRolloutPlan, currentVersion, fallbackTarget, fallbackChannel string) (target, channel string, updateRequired bool) {
	current := strings.TrimSpace(currentVersion)
	target = strings.TrimSpace(plan.DesiredVersion)
	if target == "" {
		target = strings.TrimSpace(fallbackTarget)
	}
	if target == "" {
		target = current
	}
	channel = strings.TrimSpace(plan.ReleaseChannel)
	if channel == "" {
		channel = strings.TrimSpace(fallbackChannel)
	}
	if plan.Frozen {
		return target, channel, false
	}
	updateRequired = target != "" && target != current
	return target, channel, updateRequired
}

// AgentRolloutUpdateRequest is the admin PUT body.
type AgentRolloutUpdateRequest struct {
	Intent         string `json:"intent"`
	DesiredVersion string `json:"desired_version"`
	ReleaseChannel string `json:"release_channel"`
	Reason         string `json:"reason"`
	// Frozen says which way intent=freeze is being used: true halts the fleet, false RELEASES it. A pointer so
	// "not stated" is distinguishable from "stated false".
	//
	// ★ IT EXISTS BECAUSE A HALT COULD NOT BE LIFTED (2026-08-11, found while tidying a lab after an
	// end-to-end verification — the tidy-up is what exposed it). Frozen was derived as `intent == freeze` and
	// the field in the request was ignored, so the only way to un-freeze was to send intent=rollout, whose
	// desired_version nothing consumes. Once that intent was refused as unimplemented, the freeze became
	// permanent: a control an operator can apply and never remove, which is not a control, it is damage.
	Frozen *bool `json:"frozen"`
	// Waves and Window are the fleet's schedule, authored here rather than in a file on each edge. Absent leaves
	// whatever the tenant already had — an operator halting a release must not have to restate the wave plan in
	// order to do it.
	Waves  *WaveSchedule           `json:"waves"`
	Window *agentupdate.PlanWindow `json:"window"`
}

// validateWindow refuses a maintenance window that would not mean what its author thinks.
func validateWindow(w *agentupdate.PlanWindow) error {
	if w == nil {
		return nil
	}
	for _, f := range []struct {
		name, value string
	}{{"local_start", w.LocalStart}, {"local_end", w.LocalEnd}} {
		if !isLocalClock(f.value) {
			return fmt.Errorf("%s %q is not a HH:MM local time", f.name, f.value)
		}
	}
	if w.RequireIdleMinutes < 0 {
		return fmt.Errorf("require_idle_minutes is %d: a negative value does not tighten the idle requirement, "+
			"it removes it — the device applies the condition only when it is above zero", w.RequireIdleMinutes)
	}
	if w.DeadlineDays < 0 {
		return fmt.Errorf("deadline_days is %d, which cannot be met", w.DeadlineDays)
	}
	if w.DeadlineDays > 365 {
		return fmt.Errorf("deadline_days is %d: a deadline longer than a year is a fleet that never updates, "+
			"stated as a schedule", w.DeadlineDays)
	}
	return nil
}

// isLocalClock accepts HH:MM in 24-hour form and nothing else.
func isLocalClock(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) != 5 || v[2] != ':' {
		return false
	}
	h, herr := strconv.Atoi(v[:2])
	m, merr := strconv.Atoi(v[3:])
	return herr == nil && merr == nil && h >= 0 && h <= 23 && m >= 0 && m <= 59
}

// ValidateAgentRolloutUpdate normalizes + validates an admin rollout change into a plan (UpdatedAt is
// stamped by the caller). rollout/rollback require a desired_version (you cannot advance or roll back to
// nothing); freeze does not (it pins the fleet where it is).
func ValidateAgentRolloutUpdate(req AgentRolloutUpdateRequest) (AgentRolloutPlan, error) {
	intent := strings.TrimSpace(req.Intent)
	if intent == "" {
		intent = AgentRolloutIntentRollout
	}
	switch intent {
	case AgentRolloutIntentRollout, AgentRolloutIntentRollback, AgentRolloutIntentFreeze,
		AgentRolloutIntentSchedule, AgentRolloutIntentFollow:
	default:
		return AgentRolloutPlan{}, fmt.Errorf("invalid intent %q (want rollout|rollback|freeze|schedule|follow)", intent)
	}
	desired := strings.TrimSpace(req.DesiredVersion)
	if (intent == AgentRolloutIntentRollout || intent == AgentRolloutIntentRollback) && desired == "" {
		return AgentRolloutPlan{}, fmt.Errorf("desired_version is required for intent %s", intent)
	}
	// intent=freeze means "I am deciding whether this fleet is halted", and the decision is the `frozen` field.
	// Unstated defaults to halting, because that is what somebody reaching for this endpoint in an incident
	// means — but a stated false RELEASES, and used to be silently turned back into a halt.
	frozen := intent == AgentRolloutIntentFreeze
	if intent == AgentRolloutIntentFreeze && req.Frozen != nil {
		frozen = *req.Frozen
	}
	// A reason is required in BOTH directions. Halting a fleet and releasing one are each a decision somebody
	// will have to explain later, and "why did this start moving again" is the harder question of the two.
	reason := strings.TrimSpace(req.Reason)
	if intent == AgentRolloutIntentFreeze && reason == "" {
		return AgentRolloutPlan{}, fmt.Errorf("a reason is required to halt a fleet or to release one")
	}
	if intent == AgentRolloutIntentSchedule && req.Waves == nil && req.Window == nil {
		return AgentRolloutPlan{}, fmt.Errorf("intent %s must carry a wave schedule, a window, or both",
			AgentRolloutIntentSchedule)
	}
	// The schedule is validated HERE, where it is authored, rather than on each edge that receives it: an
	// invalid wave schedule reaching devices as "frozen because the file is broken" is a fleet halted by a typo
	// somebody could have been told about at the moment they made it.
	if req.Waves != nil {
		if verr := req.Waves.Validate(); verr != nil {
			return AgentRolloutPlan{}, fmt.Errorf("wave schedule: %w", verr)
		}
	}
	// ★ AND THE WINDOW, which the comment above claimed and the code did not do (fourth review). A negative
	// require_idle_minutes is the sharp one: the device applies the idle requirement only when it is > 0, so a
	// negative number does not tighten anything — it silently REMOVES a condition an operator believes they
	// set. The rest is ordinary shape-checking, done here because an invalid window reaching devices arrives as
	// "frozen because the plan is broken", which halts a fleet over a typo somebody could have been told about.
	if verr := validateWindow(req.Window); verr != nil {
		return AgentRolloutPlan{}, fmt.Errorf("maintenance window: %w", verr)
	}
	return AgentRolloutPlan{
		Waves:          req.Waves,
		Window:         req.Window,
		DesiredVersion: desired,
		ReleaseChannel: strings.TrimSpace(req.ReleaseChannel),
		Frozen:         frozen,
		Intent:         intent,
		Reason:         reason,
	}, nil
}

// AgentRolloutStore holds the per-tenant desired rollout plan (in-memory; the desired state is small and
// re-derivable, mirroring the other admin runtime overlays).
type AgentRolloutStore struct {
	// path is where the plans are persisted. Empty keeps the old in-memory behaviour, which is only correct
	// for tests.
	path string
	// blob is the SHARED store, when the deployment has one, and it WINS over path.
	//
	// ★★★ A HALT ON ONE CONTROL PLANE IS NOT A HALT (2026-08-28, measured on a two-region deployment). This
	// store's own header says the freeze must survive a control plane's restart, because an Edge pulling an
	// empty plan replaces a halt with "not halted". A pair of control planes behind one front door is that
	// same failure without any restart: the operator halts, one node writes its disk, and every second poll
	// reaches the node that never heard and answers "not frozen". The Edge cannot tell the two apart, and it
	// should not have to — the decision belongs to the deployment, so it lives where the deployment's state
	// lives.
	blob  Persister
	mu    sync.Mutex
	plans map[string]AgentRolloutPlan
}

// Persister is the shared store this control plane keeps its plans in. It is blobstore.Persister, restated
// here so this package keeps depending on nothing.
type Persister interface {
	Load() ([]byte, error)
	Save([]byte) error
}

func NewAgentRolloutStore() *AgentRolloutStore {
	return &AgentRolloutStore{plans: map[string]AgentRolloutPlan{}}
}

// ★ THE HALT MUST SURVIVE THE CONTROL PLANE'S OWN RESTART (2026-08-11, second review). Edges now pull this
// store as the authority, and it was entirely in memory: after a CP restart the first successful fetch would
// return an EMPTY plan, and every Edge holding an incident freeze would replace it with "not halted". A
// process restart would un-withdraw a bad release, which is the one thing the freeze exists to make
// impossible.
//
// A freeze is not derivable state that can be rebuilt from somewhere else — it is a decision a person made
// during an incident, and the only copy of it was RAM.
//
// The file is written BEFORE the write is acknowledged: a 200 that outlives its own storage is the same lie in
// a different place.

// LoadFromPersister rehydrates from the SHARED store, and makes it the place later writes go. Same refusals as
// LoadFrom: an unreadable store stops the process rather than answering "not frozen" to a fleet.
func (s *AgentRolloutStore) LoadFromPersister(blob Persister) error {
	if s == nil || blob == nil {
		return nil
	}
	raw, err := blob.Load()
	if err != nil {
		return fmt.Errorf("read the shared agent rollout store: %w", err)
	}
	// Only nil denotes an absent snapshot under the Persister contract. An
	// existing zero-byte file is corrupt, not a new deployment.
	plans := make(map[string]AgentRolloutPlan)
	if raw != nil {
		plans, err = decodeRolloutSnapshot(raw)
		if err != nil {
			return fmt.Errorf("read the shared agent rollout store: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw != nil {
		s.plans = plans
	}
	s.blob = blob
	return nil
}

// LoadFrom rehydrates the store from path. A missing file is not an error — that is a control plane which has
// never been asked to halt anything.
func (s *AgentRolloutStore) LoadFrom(path string) error {
	if s == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.mu.Lock()
		s.path = path
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the agent rollout store %s: %w", path, err)
	}
	plans, jerr := decodeRolloutSnapshot(raw)
	if jerr != nil {
		// ★ NOT ignored. A halt that cannot be read is not "no halt": the caller decides, and the edge-facing
		// answer for an unreadable authority is to hold, not to release.
		return fmt.Errorf("the agent rollout store %s is unreadable (%w) — refusing to start with an unknown "+
			"halt state rather than answering \"not frozen\" to every edge", path, jerr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans = plans
	s.path = path
	return nil
}

// persistPlansLocked writes a candidate set out. Called with the lock held, by Set, BEFORE the candidate
// becomes what Get answers.
func (s *AgentRolloutStore) persistPlansLocked(plans map[string]AgentRolloutPlan) error {
	if s.blob == nil && strings.TrimSpace(s.path) == "" {
		return nil
	}
	b, err := json.MarshalIndent(plans, "", "  ")
	if err != nil {
		return err
	}
	// ★ THE SHARED STORE WINS — see the note on the field.
	if s.blob != nil {
		return s.blob.Save(b)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// ★ ONE DURABLE WRITE (2026-08-14). Hand-staged create/write/flush/close/chmod/rename — which is exactly
	// durablefile.Write. See ops/checks/one_durable_write.sh.
	return durablefile.Write(s.path, b, 0o600)
}

func (s *AgentRolloutStore) Get(tenantID string) AgentRolloutPlan {
	if s == nil {
		return AgentRolloutPlan{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plans[strings.TrimSpace(tenantID)]
}

// Apply merges a new plan into the tenant's current one and persists the result, ALL UNDER ONE LOCK.
//
// ★ WHY NOT Get-then-Set (2026-08-12, fourth review). The caller was reading the previous plan to carry the
// schedule forward and writing the merged result, with the lock released in between: two admins — one halting
// a release, one moving the maintenance window — would each read the same previous state and the later write
// would silently undo the earlier one. The merge is the part that has to be atomic, so it lives where the lock
// is.
//
// The merge rules are the operator's expectations, stated once:
//   - a schedule change does NOT touch the halt (that is what intent=schedule is for),
//   - a halt change does NOT touch the schedule (an incident is not the moment to restate a wave plan),
//   - anything the request does not carry keeps its previous value.
func (s *AgentRolloutStore) Apply(tenantID string, in AgentRolloutPlan, now time.Time) (AgentRolloutPlan, error) {
	if s == nil {
		return AgentRolloutPlan{}, nil
	}
	key := strings.TrimSpace(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()

	merged := s.plans[key]
	if in.Waves != nil {
		merged.Waves = in.Waves
	}
	if in.Window != nil {
		merged.Window = in.Window
	}
	switch in.Intent {
	case AgentRolloutIntentSchedule:
		// The halt and its reason are left exactly as they were.
	case AgentRolloutIntentFollow:
		// ★ ONLY THE VERSION IS CLEARED. Following what the deployment offers is a statement about WHICH
		// version, and it must not release a fleet somebody halted — the same rule the schedule intent has, in
		// the other direction.
		merged.DesiredVersion, merged.ReleaseChannel = "", ""
	case AgentRolloutIntentFreeze:
		// A halt/release changes movement, not the version already selected.
		merged.Frozen, merged.Reason = in.Frozen, in.Reason
		if in.DesiredVersion != "" {
			merged.DesiredVersion = in.DesiredVersion
		}
		if in.ReleaseChannel != "" {
			merged.ReleaseChannel = in.ReleaseChannel
		}
	default:
		// Selecting a version must not release an incident hold. Only an explicit
		// freeze=false decision, with its required reason, may do that.
		merged.DesiredVersion, merged.ReleaseChannel = in.DesiredVersion, in.ReleaseChannel
	}
	merged.Intent = in.Intent
	merged.UpdatedAt = now.UTC().Format(time.RFC3339)

	candidate := make(map[string]AgentRolloutPlan, len(s.plans)+1)
	for k, v := range s.plans {
		candidate[k] = v
	}
	candidate[key] = merged
	if err := s.persistPlansLocked(candidate); err != nil {
		return AgentRolloutPlan{}, err
	}
	s.plans = candidate
	return merged, nil
}

// Set records the plan and PERSISTS it before returning. The error is returned rather than logged: the caller
// answers an operator who is halting a release, and "stored" must not be said about something that was not.
func (s *AgentRolloutStore) Set(tenantID string, plan AgentRolloutPlan) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// ★ PERSIST THE CANDIDATE, THEN PUBLISH IT (2026-08-11, third review). Updating the map first meant a failed
	// write left the new plan visible to Get — which is what the EDGES pull — while the API answered 500. An
	// operator told their halt was not accepted would have had it applied anyway, and the reverse for an
	// unfreeze: told it failed, while every device resumed.
	//
	// So the write is attempted against a COPY, and the live map only moves once the bytes are down.
	key := strings.TrimSpace(tenantID)
	candidate := make(map[string]AgentRolloutPlan, len(s.plans)+1)
	for k, v := range s.plans {
		candidate[k] = v
	}
	candidate[key] = plan
	if err := s.persistPlansLocked(candidate); err != nil {
		return err
	}
	s.plans = candidate
	return nil
}

// CountForTenant is how many plans this store holds for one organization: one, or none. It exists because a
// deletion has to be able to say what is LEFT, and a store nobody counts contributes nothing to that answer.
func (s *AgentRolloutStore) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.plans[strings.TrimSpace(tenantID)]; ok {
		return 1
	}
	return 0
}

// RemoveTenant erases an organization's plan and persists the removal before returning, like every other write
// here.
//
// ★ WHAT A DELETED ORGANIZATION WAS TOLD TO RUN IS NOT SOMETHING TO KEEP (2026-08-28). The plan carries a
// desired version, a freeze and the reason a person typed for it — a record of that organization — and until
// this existed a deletion left it behind while reporting nothing remaining.
func (s *AgentRolloutStore) RemoveTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.TrimSpace(tenantID)
	if _, ok := s.plans[key]; !ok {
		return 0
	}
	candidate := make(map[string]AgentRolloutPlan, len(s.plans))
	for k, v := range s.plans {
		if k == key {
			continue
		}
		candidate[k] = v
	}
	if err := s.persistPlansLocked(candidate); err != nil {
		// The caller counts what was erased; a removal that could not be stored has not happened, and saying
		// it did is what makes an erasure report a number nobody can check.
		return 0
	}
	s.plans = candidate
	return 1
}

// Tenants lists every organization this store holds a plan for, sorted.
//
// ★ IT EXISTS SO A FLEET EDGE CAN BE ANSWERED ABOUT ALL OF THEM (2026-08-28). An Edge that serves several
// organizations and is told about one holds every other one's fleet for ever — safely, and permanently.
func (s *AgentRolloutStore) Tenants() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.plans))
	for t := range s.plans {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
