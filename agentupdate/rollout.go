package agentupdate

// rollout.go — what the control plane decided for THIS device, and the rule that keeps a freeze honest.
//
// Shared by both platforms deliberately. The decision inside — what an UNVERIFIABLE plan MEANS — is the one
// that must not be answered twice: a second answer is a platform on which damaging the plan lifts the halt.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// Rollout is what the control plane decided for this device, applied on top of the local plan.
//
// Two documents rather than one because they answer to different people. Plan is what this ENDPOINT is
// configured with — MaxAttempts, and the fallback window a device uses before it has heard from anyone.
// Rollout is what the FLEET was told, and it carries the two facts a device cannot work out for itself: the
// halt, and its wave start.
type Rollout struct {
	Plan          RolloutPlan
	Frozen        bool
	FrozenReason  string
	EligibleSince time.Time
	// Source describes where it came from, for --status and for the log line that explains a held device.
	Source string
	// PlanGeneratedAt is when the control plane produced this plan, parsed. Zero when it did not say.
	//
	// The caller persists the newest it has accepted and hands it back as RolloutExpectation.NotBefore, which is
	// what makes replaying an older signed plan useless.
	PlanGeneratedAt time.Time
	// WaveWithheld explains why this plan's wave start was NOT applied, or is empty when it was.
	//
	// ★ A plan can always STOP this device and cannot always START it. See RolloutExpectation.
	WaveWithheld string
}

// RolloutExpectation is what the device knows about its own situation, independently of the plan, and against
// which a plan is judged.
//
// ★ WHY A PLAN IS NOT SELF-SUFFICIENT (2026-08-11, from a review that read this file against the courier).
// The manifest and the plan are fetched by two independent couriers, and on failure each keeps the copy it
// already had. So "new manifest, old plan" is not an attack — it is Tuesday. Applied blindly, the old plan's
// already-open wave authorises the IMMEDIATE install of a release it was never computed for, and an old plan
// that predates a halt lifts it simply by being older. Both were possible here: the signature was checked and
// nothing else was, though RolloutPlan.TargetVersion exists and its comment says it is there "so a device can
// tell a stale plan from a current one".
//
// The asymmetry is the whole design. A plan may always HALT this device — obeying a stop is safe whoever meant
// it, and refusing to obey an old stop is how a withdrawal gets undone. A plan may only START this device when
// it demonstrably describes the release the device is being offered, is not older than one already accepted,
// and is not stale. Everything else withholds the wave and says so.
type RolloutExpectation struct {
	// Version is the release this device is currently being offered — the manifest's version. A plan computed
	// for a different one cannot authorise it.
	Version string
	// NotBefore is the newest generated_at this device has already accepted. A plan older than that is a replay
	// of a document the fleet has moved past, and it FREEZES rather than merely losing its wave: something is
	// feeding this device the past.
	NotBefore time.Time
	// MaxAge bounds how old a plan may be and still authorise a wave. Zero means unbounded, which is only
	// correct for callers that have no clock to compare against.
	MaxAge time.Duration
	// DeviceIdentity and TenantID are who this device is. A plan names both — the Edge signs one PER DEVICE —
	// and without them a plan issued for a device in an earlier wave could be dropped onto a later one to
	// authorise it early. The signature does not help: it is a valid plan, for somebody else.
	//
	// ★ EMPTY MEANS "THIS DEVICE CANNOT CHECK", NOT "IT MATCHES". The updater deliberately holds no network
	// identity, so it learns this from the running extension's marker; an extension that is stopped, or a build
	// that predates recording it, leaves it unknown. Unknown is reported in Source rather than silently
	// treated as a pass — and it does not hold the fleet, because an upgrade ordering problem must not become
	// an outage. The check becomes real as the fleet updates, and until then it is VISIBLE that it is not.
	DeviceIdentity string
	TenantID       string
}

// DefaultPlanMaxAge is how stale a rollout plan may be before it stops being able to start an install.
//
// The courier refreshes every 15 minutes, so anything approaching a day means this device has not heard from
// the fleet in a very long time — during which a release may have been withdrawn. It keeps obeying the last
// halt it was told about; what it stops doing is treating an old go-ahead as current.
const DefaultPlanMaxAge = 24 * time.Hour

// PlanClockSkewTolerance is how far ahead of this device a plan may claim to have been generated before it is
// treated as undatable. Two machines' clocks disagree; a plan from tomorrow is not a clock disagreement.
const PlanClockSkewTolerance = 5 * time.Minute

// ★ ErrPlanUnverifiable is the state that must NOT read as "no plan".
//
// A plan file that exists and does not verify is treated as a FREEZE, and this is the load-bearing decision in
// the whole withdrawal mechanism. The freeze is what stops a bad release on devices that already hold its
// manifest. If a plan the device cannot verify fell back to the default — which is not frozen — then corrupting
// the file, truncating it, or stripping its signature would LIFT a halt. The cheapest possible attack on the
// safety control would be to damage it.
//
// So: absent plan means no plan (the ordinary un-provisioned device), and unverifiable plan means stop.
var ErrPlanUnverifiable = errors.New("the rollout plan could not be verified")

// LoadRollout reads the couriered plan and decides what it means.
//
// trustedKeys empty is the opt-out, and it is a real choice rather than a default: without a pin the payload is
// read WITHOUT verification, so the freeze is only as strong as the file's permissions. That is acceptable on a
// box whose %ProgramData%\DSSE is SYSTEM-only (datadir.Ensure) and it is stated loudly, because a deployment
// that wants withdrawal to be tamper-evident has to pin the key.
func LoadRollout(path string, trustedKeys []string, now time.Time, exp RolloutExpectation) (Rollout, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// The ordinary state of a device nobody has published a rollout to. NOT a freeze: a fleet that never
		// configured this must not be halted by the absence of a file it was never sent.
		return Rollout{Source: "no rollout plan on this device"}, nil
	}
	if err != nil {
		// Present but unreadable. Frozen, for the reason on ErrPlanUnverifiable: this is the shape damaging the
		// file takes, and it must not be the shape lifting a halt takes.
		return frozenBy(fmt.Sprintf("the rollout plan at %s could not be read (%v)", path, err)),
			fmt.Errorf("%w: %v", ErrPlanUnverifiable, err)
	}

	var env agentpolicy.Envelope
	if jerr := json.Unmarshal(raw, &env); jerr != nil || env.PayloadB64 == "" {
		// ★ NOT AN ENVELOPE. On an Edge with no agent-policy signer the plan route serves the payload as a bare
		// JSON object, and that deployment must not be a fleet that freezes itself.
		//
		// The PIN decides, which is the same contract as everywhere else here: a device that pinned a key asked
		// for tamper-evidence, so an unsigned document is exactly the substitution it asked to be protected
		// from and it freezes. A device with no pin has opted out — it already accepts an unverified envelope,
		// and refusing the unsigned FORM while accepting unverified CONTENT would be a distinction with no
		// security in it and a halted lab behind it.
		//
		// Found by probing rather than by reading: with no pin, a bare plan froze the device, so the default
		// lab deployment (Edge without a signer) would have halted every machine the moment a plan appeared.
		if len(trustedKeys) == 0 {
			p, perr := DecodeRolloutPlan(raw)
			if perr != nil {
				return frozenBy(fmt.Sprintf("the rollout plan at %s is neither a signed envelope nor a readable "+
					"plan (%v)", path, perr)), fmt.Errorf("%w: %v", ErrPlanUnverifiable, perr)
			}
			return decideRollout(p, path, now, exp,
				"UNVERIFIED and UNSIGNED (this edge has no plan-signing key and this device pins none, "+
					"so the freeze is only as strong as this file's permissions)")
		}
		return frozenBy(fmt.Sprintf("the rollout plan at %s is not a signed envelope, and this device pins a "+
			"plan-signing key", path)), fmt.Errorf("%w: not a signed envelope", ErrPlanUnverifiable)
	}
	// Type BEFORE signature, the same order Open uses: one key signs several documents here and the
	// signature check is pure crypto that does not look at the kind, so a valid signature over the wrong sort of
	// artefact must be reported as the substitution it is rather than decoded and hoped about.
	if env.Type != RolloutPlanEnvelopeType {
		return frozenBy(fmt.Sprintf("the document at %s is a %q, not a rollout plan", path, env.Type)),
			fmt.Errorf("%w: envelope type %q, want %q", ErrPlanUnverifiable, env.Type, RolloutPlanEnvelopeType)
	}

	var payload []byte
	source := ""
	if len(trustedKeys) == 0 {
		// Unpinned: decode without verifying, and say so every time. Silence here would let a device look
		// protected while its halt can be rewritten by anyone who can write the file.
		b, derr := base64.StdEncoding.DecodeString(env.PayloadB64)
		if derr != nil {
			return frozenBy(fmt.Sprintf("the rollout plan at %s has an unreadable payload", path)),
				fmt.Errorf("%w: %v", ErrPlanUnverifiable, derr)
		}
		payload = b
		source = "UNVERIFIED (no plan-signing key is pinned on this device, so the freeze is only as strong as this file's permissions)"
	} else {
		b, verr := agentpolicy.VerifyAny(env, trustedKeys)
		if verr != nil {
			return frozenBy(fmt.Sprintf("the rollout plan at %s did not verify (%v)", path, verr)),
				fmt.Errorf("%w: %v", ErrPlanUnverifiable, verr)
		}
		payload = b
		source = "verified against the pinned plan-signing key"
	}

	p, perr := DecodeRolloutPlan(payload)
	if perr != nil {
		return frozenBy(fmt.Sprintf("the rollout plan at %s is malformed (%v)", path, perr)),
			fmt.Errorf("%w: %v", ErrPlanUnverifiable, perr)
	}
	return decideRollout(p, path, now, exp, source)
}

// decideRollout is everything that happens AFTER a plan has been read, whichever way it was read.
//
// ★ IT IS ONE FUNCTION BECAUSE THERE ARE TWO EXITS (2026-08-11). LoadRollout returns from two places — the
// signed envelope, and the bare JSON an edge without a signer serves — and the freshness and binding checks
// were added to only one of them. The tests, written against the bare form, passed while a signed plan was
// judged and an unsigned one was not: a rule split across two exits is a rule that holds on one of them.
func decideRollout(p RolloutPlan, path string, now time.Time, exp RolloutExpectation, source string) (Rollout, error) {
	since, terr := p.EligibleSinceTime()
	if terr != nil {
		return frozenBy(fmt.Sprintf("the rollout plan at %s carries an unusable wave start (%v)", path, terr)),
			fmt.Errorf("%w: %v", ErrPlanUnverifiable, terr)
	}

	generated, gerr := time.Parse(time.RFC3339, p.GeneratedAt)
	if p.GeneratedAt != "" && gerr != nil {
		return frozenBy(fmt.Sprintf("the rollout plan at %s says it was generated at %q, which is not a time",
			path, p.GeneratedAt)), fmt.Errorf("%w: generated_at %q: %v", ErrPlanUnverifiable, p.GeneratedAt, gerr)
	}

	// ★ A PLAN FROM THE FUTURE MUST NOT MOVE THE RATCHET (2026-08-11, found by reading a live device's status
	// against the clock while adding the ratchet itself). The floor is "the newest plan accepted", so accepting
	// one dated next year sets a floor no legitimate plan can ever clear: every subsequent plan reads as a
	// replay and the device freezes permanently. A control-plane clock set wrong would do this to a whole fleet,
	// and the symptom would accuse the fleet of being attacked.
	//
	// So a future-dated plan keeps its halt, loses its wave, and does NOT raise the floor. The tolerance is for
	// ordinary skew between two machines, not for a plan that claims to be from tomorrow.
	if !generated.IsZero() && generated.After(now.Add(PlanClockSkewTolerance)) {
		out := Rollout{Plan: p, Frozen: p.Frozen, FrozenReason: p.FrozenReason, Source: source}
		out.WaveWithheld = fmt.Sprintf("this plan says it was generated %s, which is in this device's FUTURE "+
			"(now %s) — its age cannot be established, and accepting it would set a floor no later plan could "+
			"clear. Check the clock on the machine that generated it",
			generated.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		out.Source += " — WAVE WITHHELD: " + out.WaveWithheld
		return out, nil
	}

	// ★★ WHOSE PLAN IS THIS, ASKED BEFORE ITS AGE (2026-08-13, thirtieth review #18). The twenty-ninth review
	// established that a plan addressed to another device must not move this device's replay floor — and put
	// that check BELOW the replay branch, which therefore still fired first. So a misdelivered OLD plan froze
	// this machine anyway, and since the same round it does so with ErrPlanUnverifiable, which classifies it as
	// an attack. Two halves of one fix disagreeing about whether another device's plan may touch this device's
	// replay state.
	//
	// A document this device may not act on cannot be a replay OF this device's history. Its freeze still
	// applies below — a halt is obeyed by whoever receives it — and its wave is withheld by the switch further
	// down, which is the whole asymmetry this file is built on.
	addressedElsewhere := (p.DeviceIdentity != "" && exp.DeviceIdentity != "" &&
		!strings.EqualFold(p.DeviceIdentity, exp.DeviceIdentity)) ||
		(p.TenantID != "" && exp.TenantID != "" && !strings.EqualFold(p.TenantID, exp.TenantID))

	// ★ REPLAY. A correctly signed plan older than one this device already accepted is not a stale copy — a
	// stale copy is what the courier keeps when a fetch fails, and that one is not OLDER than what was accepted,
	// it IS what was accepted. Being handed the past means something is choosing which past to hand over, and
	// the most useful past to an attacker is the one from before a release was withdrawn.
	if !addressedElsewhere && !exp.NotBefore.IsZero() && !generated.IsZero() && generated.Before(exp.NotBefore) {
		// ★ AND IT IS AN UNVERIFIABLE PLAN, LIKE EVERY OTHER FREEZE HERE (2026-08-13, twenty-ninth review).
		// This branch alone returned nil, so a REPLAY — the one freeze that means somebody handed this device
		// a document on purpose — was recorded the same way as a halt an operator authored. The caller cannot
		// tell "the fleet is stopped" from "this device was attacked".
		return frozenBy(fmt.Sprintf("the rollout plan at %s was generated %s, which is OLDER than one this device "+
				"has already accepted (%s) — a halt cannot be lifted by replaying an earlier document", path,
				generated.UTC().Format(time.RFC3339), exp.NotBefore.UTC().Format(time.RFC3339))),
			fmt.Errorf("%w: the plan is older than one already accepted", ErrPlanUnverifiable)
	}

	out := Rollout{Plan: p, Frozen: p.Frozen, FrozenReason: p.FrozenReason, EligibleSince: since, Source: source,
		PlanGeneratedAt: generated}

	// ★ A PLAN ADDRESSED TO SOMEBODY ELSE MUST NOT MOVE THIS DEVICE'S REPLAY FLOOR (2026-08-13, twenty-ninth
	// review). The floor is a one-way ratchet the callers persist from PlanGeneratedAt, and it was set for any
	// plan that parsed — including one whose device identity or tenant says it is not for this machine. So a
	// single misdelivered file, correctly signed and newer, raised this device's floor above its OWN plan, and
	// every subsequent legitimate plan tripped the replay freeze. Permanent, and only liftable by the control
	// plane issuing something newer still: one wrong file is a denial of service on that machine.
	//
	// A document this device may not act on is not a document it has accepted. The floor moves for plans that
	// are for THIS device; the freeze inside such a plan still applies, because a halt is obeyed by anyone who
	// receives it — that asymmetry is the whole design and it is why this is not simply "reject it".
	if addressedElsewhere {
		out.PlanGeneratedAt = time.Time{}
	}

	// ★ From here on, the plan keeps its power to STOP and may lose its power to START.
	switch {
	case p.DeviceIdentity != "" && exp.DeviceIdentity != "" && !strings.EqualFold(p.DeviceIdentity, exp.DeviceIdentity):
		out.WaveWithheld = fmt.Sprintf("this plan is addressed to %s and this device is %s — a plan issued for "+
			"another device cannot open this one's wave, however validly it was signed", p.DeviceIdentity,
			exp.DeviceIdentity)
	case p.TenantID != "" && exp.TenantID != "" && !strings.EqualFold(p.TenantID, exp.TenantID):
		out.WaveWithheld = fmt.Sprintf("this plan belongs to tenant %s and this device belongs to %s",
			p.TenantID, exp.TenantID)
	case strings.TrimSpace(exp.Version) == "":
		// The caller is not offering anything (no manifest). There is no wave to authorise.
		out.WaveWithheld = "no release is being offered to this device, so no wave applies"
	case strings.TrimSpace(p.TargetVersion) == "":
		out.WaveWithheld = "this plan does not say which release its wave was computed for, so it cannot " +
			"authorise one"
	case !SameVersion(p.TargetVersion, exp.Version):
		out.WaveWithheld = fmt.Sprintf("this plan's wave was computed for %s and this device is being offered "+
			"%s — a wave that opened for one release does not open another", p.TargetVersion, exp.Version)
	case generated.IsZero():
		out.WaveWithheld = "this plan does not say when it was generated, so its age cannot be established"
	case exp.MaxAge > 0 && now.Sub(generated) > exp.MaxAge:
		out.WaveWithheld = fmt.Sprintf("this plan was generated %s ago (limit %s) — this device has not heard "+
			"from the fleet in long enough that a release could have been withdrawn since",
			now.Sub(generated).Round(time.Minute), exp.MaxAge)
	}
	if out.WaveWithheld != "" {
		out.EligibleSince = time.Time{}
		out.Source += " — WAVE WITHHELD: " + out.WaveWithheld
	} else if p.DeviceIdentity != "" && exp.DeviceIdentity == "" {
		// Said, not skipped: a check that cannot run must be visible, or its absence becomes indistinguishable
		// from its success.
		out.Source += " — ★ this device could not confirm the plan is addressed to it (its own identity is " +
			"unknown here: the agent is stopped, or predates recording it)"
	}
	return out, nil
}

// frozenBy is the safe answer for every way a present plan can fail to be understood.
func frozenBy(why string) Rollout {
	return Rollout{
		Frozen: true,
		FrozenReason: why + " — holding this device rather than falling back to an unfrozen default, because " +
			"damaging the plan must not be a way to lift a halt",
		Source: why,
	}
}
