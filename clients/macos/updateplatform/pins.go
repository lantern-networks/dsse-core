// pins.go — which signing keys this device trusts for updates, and where they come from on macOS.
//
// ★ WHY THIS FILE EXISTS (2026-08-11). The shipped macOS package installed the updater LaunchDaemon with no
// pinned keys at all. The daemon ran, evaluated every 30 minutes, and said on every single pass:
//
//	★ WARNING no update-signing key is pinned, so this device can NEVER update.
//
// It was not wrong and it was not quiet — it was writing to a root-only log nobody reads. So the fleet carried
// a security agent with an auto-update mechanism that was fully built, correctly refusing, and structurally
// incapable of ever updating anything. The Windows MSI takes -UpdatePin and validates it; the macOS package
// passed nothing. One product, one platform wired.
//
// ★ AND THE KEYS COME FROM THE AGENT CONFIG, NOT THE BINARY. Windows bakes them in at MSI build time, which is
// right there — that package is built per deployment. The macOS package is deliberately generic and
// distributable (docs/oss_signed_distribution_design.md), so baking a tenant's key into it would force a
// per-tenant build-and-notarize, which is the thing that decision rejected. The tenant-specific material
// arrives the way all the other tenant-specific material now does: in agent_config.json, which the installer
// refuses to install without.
//
// This does not weaken the trust boundary. Both the binary and the config live in a root-owned directory, so
// substituting either one already requires root — and with root you can replace the updater outright. What it
// DOES mean is that the agent config now carries an authority to run code, so its ownership matters in a way
// it did not before; the package enforces that, and says so.
package updateplatform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// AgentConfigPath is the configuration the provider already reads and the installer already requires. The
// updater reads the same file rather than introducing a second one: two files that must agree is a way to be
// configured and not configured at the same time.
func AgentConfigPath() string { return filepath.Join(DataRoot, "agent_config.json") }

// Pins are the two authorities, deliberately separate.
//
// Update signs the MANIFEST: it says WHAT code may run, and holding it is equivalent to root on every device
// in the fleet. Plan signs the ROLLOUT: it says WHEN, and carries the freeze that halts a bad release. They
// are different powers and must not be the same key — a fleet whose "stop" is signed by the key that says
// "go" has no stop.
type Pins struct {
	Update []string
	Plan   []string
}

type agentConfigPins struct {
	Update []string `json:"update_signing_keys"`
	// ★ The plan key is NOT a field of its own. The rollout plan is signed by the agent-policy key, and the
	// network extension already reads that key from THIS field — it is the device's provisioned pin. An earlier
	// version of this file invented "plan_signing_keys" beside it, which is a second place for one fact and
	// therefore a way for the two to disagree.
	AgentPolicyPin string `json:"network_extension_agent_policy_signing_public_key"`
}

// LoadPins reads the keys from the agent configuration.
//
// Every failure is returned, never swallowed. A device that cannot read its keys and a device that has none
// configured must not produce the same outcome as a device that is correctly pinned — that equivalence is the
// entire defect this file was written for.
func LoadPins(path string) (Pins, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Pins{}, fmt.Errorf("read the agent configuration %s: %w", path, err)
	}
	var cfg agentConfigPins
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Pins{}, fmt.Errorf("the agent configuration %s is not valid JSON: %w", path, err)
	}

	update, err := normalizeKeys(cfg.Update, "update_signing_keys")
	if err != nil {
		return Pins{}, err
	}
	plan, err := normalizeKeys([]string{cfg.AgentPolicyPin}, "network_extension_agent_policy_signing_public_key")
	if err != nil {
		return Pins{}, err
	}

	// ★ The separation is enforced here, not merely documented. Reusing one key for both means whoever can
	// authorise a release can also authorise the plan that says the fleet is not frozen — so the halt control
	// is signed by the party a halt exists to stop.
	for _, u := range update {
		for _, p := range plan {
			if strings.EqualFold(u, p) {
				return Pins{}, fmt.Errorf("update_signing_keys and plan_signing_keys share the key %s — the key "+
					"that authorises RUNNING CODE must not also authorise the rollout plan that can lift a freeze", u)
			}
		}
	}
	return Pins{Update: update, Plan: plan}, nil
}

// TrustAnchorPointerPath is where the network extension records the trust material it has ADOPTED, including
// the agent-policy public keys — the same keys that sign the rollout plan.
func TrustAnchorPointerPath() string { return filepath.Join(DataRoot, "trust_anchor_pointer.json") }

type trustAnchorPointer struct {
	AgentPolicyPublicKeys []string `json:"agent_policy_public_keys"`
}

// PlanKeys answers which keys may sign the rollout plan.
//
// ★ IT IS THE UNION, because that is what the network extension verifies with: its provisioned PIN plus every
// key it has adopted from a signed trust bundle (DsseSignedAgentPolicy takes `[pinnedPublicKeyHex] + alsoAccept`).
// The updater checks the same envelope type signed by the same key, so any narrower set is a validator stricter
// than the verifier — which is how this went wrong twice already. Reading only the adopted set found nothing on
// a device whose Edge publishes no key for adoption, and reported "no plan key" about a machine that verifies
// policy perfectly well every minute.
//
// The two sources have different lifetimes and that is the point of having both. The pin is what the device was
// provisioned with and never changes on its own; the adopted set is how a key ROTATES, arriving inside a bundle
// signed by the key already in force. Take either away and one of the two normal states stops working.
// updateKeysInForce is what this device will actually verify a RELEASE against — the flag when one was given,
// the agent config otherwise. It is a parameter because only the caller knows which won.
func PlanKeys(pointerPath, agentConfigPath string, updateKeysInForce []string) (keys []string, source string) {
	var out []string
	var sources []string

	pins, err := LoadPins(agentConfigPath)
	switch {
	case err != nil:
		sources = append(sources, fmt.Sprintf("★ the agent config could not be read (%v)", err))
	case len(pins.Plan) > 0:
		out = append(out, pins.Plan...)
		sources = append(sources, "the provisioned pin in "+agentConfigPath)
	}

	if raw, rerr := os.ReadFile(pointerPath); rerr == nil {
		var p trustAnchorPointer
		if json.Unmarshal(raw, &p) == nil && len(p.AgentPolicyPublicKeys) > 0 {
			adopted, kerr := normalizeKeys(p.AgentPolicyPublicKeys, "agent_policy_public_keys")
			switch {
			case kerr != nil:
				// ★ SAID, not skipped. A device that HAS adopted keys and cannot use them is a different
				// situation from one that adopted none, and only the first is a defect.
				sources = append(sources, fmt.Sprintf("★ %d adopted key(s) this build cannot use: %v",
					len(p.AgentPolicyPublicKeys), kerr))
			default:
				// ★ THE SEPARATION HAS TO SURVIVE ROTATION (2026-08-11, from a review). LoadPins refuses an agent
				// config whose update key IS its plan key — one key signing both "what to run" and "whether to
				// halt" means the party a freeze exists to stop is the party who signs the freeze. That check ran
				// once, over the provisioned pins. These keys arrive later, through the trust bundle, and rotate
				// there; nothing re-checked them, so the separation could be dissolved by a rotation nobody read
				// as a security change.
				//
				// The colliding key is DROPPED rather than the whole plan refused. If it was the only plan key,
				// the caller below already answers "no plan-signing key" with a freeze, which is the safe end
				// state — and a device that still has another usable key keeps verifying halts.
				// ★ AN EMPTY UPDATE-KEY SET MAKES THIS CHECK VACUOUS, SO IT IS NOT RUN (2026-08-13,
				// twenty-ninth review). When the agent config could not be READ, pins.Update is empty and
				// containsFold compares every adopted key against nothing — the separation passes because
				// there is nothing to collide with, not because there is no collision. The one control that
				// keeps a compromised release key from also signing the halt disappears exactly when the file
				// it depends on is unreadable.
				//
				// So an unknown update-key set refuses the adopted keys rather than blessing them. The caller
				// below then answers "no plan-signing key", which is the state this device is genuinely in.
				// ★★ "UNKNOWN" IS NOT THE SAME AS "NONE", AND THE FIRST VERSION CONFLATED THEM (2026-08-13,
				// thirtieth review #8). The refusal below is right when this device cannot tell what its release
				// key is; it fired whenever pins.Update was EMPTY, which is also the state of a perfectly healthy
				// device whose update key came from --update-pin. Such a device had every rotation key dropped
				// and was told, untruthfully, that its config could not be read — and then froze the next time
				// the plan key rotated, for a reason its own diagnostics denied.
				//
				// ★ AND THE FLAG NOW GOES THROUGH THE SEPARATION CHECK (the second half of the twenty-ninth
				// review's #18, left open). LoadPins refuses a CONFIG whose update key is its plan key; a key
				// supplied by flag bypassed that entirely, so the one pairing this rule exists to prevent — the
				// party a freeze stops also signing the freeze — was reachable from the command line.
				updateKeys := updateKeysInForce
				if len(updateKeys) == 0 {
					updateKeys = pins.Update
				}
				if err != nil && len(updateKeysInForce) == 0 {
					sources = append(sources, "★ REFUSED every adopted plan key: this device's UPDATE-signing "+
						"keys are unknown (the agent config could not be read and no key was supplied), so the "+
						"rule that one key must not sign both the release and the halt cannot be checked — and a "+
						"check that cannot run must not pass")
					adopted = nil
				}
				for _, k := range adopted {
					if containsFold(updateKeys, k) {
						sources = append(sources, fmt.Sprintf("★ REFUSED an adopted plan key that is also this "+
							"device's UPDATE-signing key (%s…): one key signing both the release and the halt "+
							"means a compromised release key can also unfreeze the fleet", k[:min(8, len(k))]))
						continue
					}
					if !contains(out, k) {
						out = append(out, k)
					}
				}
				sources = append(sources, fmt.Sprintf("%d adopted from %s", len(adopted), pointerPath))
			}
		}
	}

	if len(out) == 0 {
		// ★ IT DOES NOT FREEZE, AND SAYING SO WAS THE DANGEROUS PART (2026-08-13). This message claimed the
		// device "holds itself frozen rather than trusting an unsigned halt". agentupdate.LoadRollout does the
		// opposite with no keys, deliberately and for a stated reason: a device that pinned nothing has opted
		// out of tamper-evidence, so refusing the unsigned FORM while accepting unverified CONTENT would be a
		// distinction with no security in it — and a lab Edge without a signer would halt every machine the
		// moment a plan appeared.
		//
		// So the behaviour is right and the sentence was wrong, which is worse than either alone: an operator
		// reading it believes the fleet is fail-frozen while a couriered plan is being accepted unverified.
		return nil, "NO PLAN-SIGNING KEY: " + strings.Join(sources, "; ") +
			" — the rollout plan is accepted UNVERIFIED (this device pins nothing, so the freeze/wave/window it " +
			"carries is only as strong as the file's permissions). Pin the Edge's agent-policy public key to " +
			"make the plan tamper-evident."
	}
	return out, strings.Join(sources, " + ")
}

// containsFold is the same comparison LoadPins uses for the provisioned pair: hex keys differing only in case
// are the same key, and a check that misses that is a check an accident walks through.
func containsFold(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func normalizeKeys(in []string, field string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, k := range in {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		// Ed25519 public keys are 32 bytes. A key of any other length is a typo, a truncation, or a different
		// kind of key entirely, and accepting it would produce a device that verifies nothing while appearing
		// configured.
		// ★ The SAME predicate the verifier uses, not a copy of it. An earlier version of this accepted only
		// 64-hex Ed25519 — which silently rejected the ECDSA-P256 key the config-signing HSM switch put in
		// force, dropped the device's adopted plan key, and left the release freeze unverified.
		if !agentpolicy.AcceptedPublicKeyHex(k) {
			return nil, fmt.Errorf("%s contains %q, which is not a key this device can verify against "+
				"(hex Ed25519, 64 chars; or hex ECDSA-P256 uncompressed point, 130 chars beginning 04)", field, k)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out, nil
}
