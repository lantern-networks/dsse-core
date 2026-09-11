package main

// pins_present.go — five verification conditions, on two services, each with its own shape.
//
// ★★★ WHY THIS IS NOT pinArgs. pinArgs replaces both of DsseSteer's pins with one value, and that is correct
// where it is used: provisioning, where an operator has just placed a key and is declaring what this device
// shall verify against. Restoration is a different act. It happens unattended, inside an upgrade, with nobody
// watching — and there the same behaviour would silently overwrite a condition the device already held.
//
// ★★★ AND WHY ONE KEY ON ONE SERVICE WAS WRONG TWICE OVER.
//
// The first version kept a single adopted key and filled every empty pin with it, which turned a box holding
// A/B/C into A/A/A — every pin individually plausible, the separation between three authorities silently gone.
//
// The second version kept three, and put all three on DsseSteer. They do not live there. Measured against the
// package that installs them (DsseAgent.wxs SteerArgs and UpdaterArgs):
//
//	DsseSteer     --config-pin          who signs this device's configuration
//	              --agent-policy-pin    who signs the policy the agent enforces
//	DsseUpdater   --update-pin          which VERSION may run   (comma-separated key SET)
//	              --plan-pin            who signs the rollout plan — WHEN, not what
//	              --update-publisher    who BUILT the bytes      (not a key at all)
//
// DsseSteer has no --update-pin flag. Restoring one into its ImagePath would hand the agent an argument it
// does not accept, and the service that could not start after an upgrade would then have been broken by the
// code written to stop exactly that. The A/B/C test that "passed" only did so because the flag had been put
// on DsseSteer by hand, which is not a shape the product ever produces — a positive control that tested the
// test.
//
// ★ AND THE SHAPES DIFFER. --config-pin and --agent-policy-pin are Ed25519, 64 hex. --update-pin and
// --plan-pin also accept a 130-character uncompressed ECDSA-P256 point beginning 04, which is what a PKCS#11
// token holds and what the control plane signs with; --update-pin is additionally comma-separated, because
// pinning old AND new is how a key rotation is carried out. --update-publisher is a requirement string,
// subject: or thumbprint:. Validating all five as 64 hex would refuse a legal fleet its own update key.

import (
	"fmt"
	"strings"
)

// pinPurpose is one verification condition: which service carries it, the flag that does, the registry value
// that survives an upgrade, and what a legal value looks like.
type pinPurpose struct {
	Service   string
	Flag      string
	ValueName string
	What      string
	Validate  func(string) error
}

// pinPurposes is the whole set. Adding a sixth condition is an edit here and nowhere else: the capture, the
// store, the restore and the report all walk this table, and they walk it per (service, flag).
var pinPurposes = []pinPurpose{
	{
		Service: "DsseSteer", Flag: "--config-pin", ValueName: "Steer_ConfigPin",
		What: "who signs this device's configuration", Validate: validateEd25519Key,
	},
	{
		Service: "DsseSteer", Flag: "--agent-policy-pin", ValueName: "Steer_AgentPolicyPin",
		What: "who signs the policy the agent enforces", Validate: validateEd25519Key,
	},
	{
		Service: "DsseUpdater", Flag: "--update-pin", ValueName: "Updater_UpdatePin",
		What: "which version this device may run", Validate: validateKeySet,
	},
	{
		Service: "DsseUpdater", Flag: "--plan-pin", ValueName: "Updater_PlanPin",
		What: "who signs the rollout plan", Validate: validateVerificationKey,
	},
	{
		Service: "DsseUpdater", Flag: "--update-publisher", ValueName: "Updater_Publisher",
		What: "who must have built the bytes", Validate: validatePublisher,
	},
}

// purposesFor returns the conditions carried by one service.
func purposesFor(service string) []pinPurpose {
	var out []pinPurpose
	for _, p := range pinPurposes {
		if strings.EqualFold(p.Service, service) {
			out = append(out, p)
		}
	}
	return out
}

// servicesWithPurposes lists the services that carry any condition, in a stable order.
func servicesWithPurposes() []string {
	var out []string
	for _, p := range pinPurposes {
		seen := false
		for _, s := range out {
			if s == p.Service {
				seen = true
			}
		}
		if !seen {
			out = append(out, p.Service)
		}
	}
	return out
}

// validateEd25519Key is the profile-signing shape: 64 hex characters.
func validateEd25519Key(v string) error {
	if !isProfileSigningKey(v) {
		return fmt.Errorf("expected 64 hex characters (an Ed25519 public key), got %d", len(v))
	}
	return nil
}

// validateVerificationKey accepts either shape the updater documents: a 64-character Ed25519 key, or a
// 130-character uncompressed ECDSA-P256 point beginning 04 — the second is what a PKCS#11 token holds, and
// refusing it would strand every fleet whose control plane signs with one.
func validateVerificationKey(v string) error {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case isProfileSigningKey(v):
		return nil
	case len(v) == 130 && strings.HasPrefix(v, "04") && isHex(v):
		return nil
	}
	return fmt.Errorf("expected 64 hex characters (Ed25519) or 130 beginning 04 (uncompressed P-256), got %d", len(v))
}

// validateKeySet accepts the comma-separated form --update-pin uses. Pinning old AND new is how a rotation is
// carried out, so a set is the normal state of a fleet mid-rotation and not an oddity to reject.
func validateKeySet(v string) error {
	parts := strings.Split(v, ",")
	seen := 0
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := validateVerificationKey(p); err != nil {
			return fmt.Errorf("key %d of %d: %w", seen+1, len(parts), err)
		}
		seen++
	}
	if seen == 0 {
		return fmt.Errorf("holds no key")
	}
	return nil
}

// validatePublisher checks the requirement's shape rather than its content: subject: is matched as a substring
// of the Authenticode subject and thumbprint: is an exact leaf hash, and which of the two a deployment uses is
// its business. What must not survive is a value in neither form, which VerifyPublisher would refuse at the
// moment an update is needed.
func validatePublisher(v string) error {
	switch {
	case strings.HasPrefix(v, "subject:") && strings.TrimSpace(strings.TrimPrefix(v, "subject:")) != "":
		return nil
	case strings.HasPrefix(v, "thumbprint:") && strings.TrimSpace(strings.TrimPrefix(v, "thumbprint:")) != "":
		return nil
	}
	return fmt.Errorf("expected subject:<Authenticode subject> or thumbprint:<leaf SHA-256>")
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// pinSet holds one value per purpose, keyed by ValueName so two services cannot collide. An absent entry means
// "this device names none", which is deliberately distinct from an entry holding "".
type pinSet map[string]string

func (p pinSet) get(valueName string) string { return strings.TrimSpace(p[valueName]) }

// empty reports whether nothing at all is held, which is the "there is nothing to restore from" case.
func (p pinSet) empty() bool {
	for _, purpose := range pinPurposes {
		if p.get(purpose.ValueName) != "" {
			return false
		}
	}
	return true
}

// pinsInArgs reads the conditions ONE service carries out of its argument list, in either the separated or the
// joined form and in both the one- and two-dash spellings. The LAST occurrence wins, because that is what Go's
// flag package does — the report has to describe the value that will actually be used.
//
// Only that service's purposes are read: finding --update-pin on DsseSteer would mean something has gone wrong
// upstream, and recording it would carry the mistake across the upgrade.
func pinsInArgs(service string, args []string) pinSet {
	out := pinSet{}
	purposes := purposesFor(service)
	for i := 0; i < len(args); i++ {
		name, value, joined := splitFlag(args[i])
		for _, purpose := range purposes {
			if name != purpose.Flag && name != purpose.Flag[1:] {
				continue
			}
			switch {
			case joined:
				out[purpose.ValueName] = value
			case i+1 < len(args):
				out[purpose.ValueName] = args[i+1]
				i++
			}
		}
	}
	for k, v := range out {
		out[k] = strings.TrimSpace(v)
	}
	return out
}

func splitFlag(a string) (name, value string, joined bool) {
	if i := strings.Index(a, "="); i >= 0 {
		return a[:i], a[i+1:], true
	}
	return a, "", false
}

// pinRestoration is what filling one service's missing conditions would do, decided before anything is written
// so the caller can report it whether or not it acts.
type pinRestoration struct {
	Service string
	Args    []string
	Added   []string // flags filled in from the stored value for THAT (service, flag)
	Kept    []string // already naming the stored value
	Differs []string // present and DIFFERENT — never overwritten
	Unheld  []string // absent here and absent from the store: nothing restored, nothing guessed
	Note    string
}

// Changed reports whether the service configuration would actually be rewritten.
func (r pinRestoration) Changed() bool { return len(r.Added) > 0 }

// fillMissingPins appends only the conditions that are absent AND have a stored value for their own (service,
// flag). It never touches one that is present, and never fills one purpose from another purpose's value.
func fillMissingPins(service string, args []string, stored pinSet) pinRestoration {
	present := pinsInArgs(service, args)
	r := pinRestoration{Service: service, Args: append([]string(nil), args...)}

	for _, purpose := range purposesFor(service) {
		current, want := present.get(purpose.ValueName), stored.get(purpose.ValueName)
		switch {
		case current == "" && want == "":
			// ★ NOT AN ERROR AND NOT A GAP TO FILL. A device that never had an update publisher does not
			// acquire one because a config pin exists. Reported so the absence is visible, and left alone.
			r.Unheld = append(r.Unheld, purpose.Flag)
		case current == "":
			r.Args = append(r.Args, purpose.Flag, want)
			r.Added = append(r.Added, purpose.Flag)
		case want == "" || current == want:
			r.Kept = append(r.Kept, purpose.Flag)
		default:
			r.Differs = append(r.Differs, purpose.Flag)
		}
	}
	r.Note = describeRestoration(r)
	return r
}

func describeRestoration(r pinRestoration) string {
	var parts []string
	if len(r.Added) > 0 {
		parts = append(parts, "restored "+strings.Join(r.Added, " and ")+" on "+r.Service)
	}
	if len(r.Differs) > 0 {
		parts = append(parts, "★ left "+strings.Join(r.Differs, " and ")+
			" alone because they name a different value from the stored one")
	}
	if len(r.Unheld) > 0 {
		parts = append(parts, strings.Join(r.Unheld, " and ")+
			" are named neither by "+r.Service+" nor by the store, so nothing was invented for them")
	}
	if len(parts) == 0 {
		return r.Service + ": every condition already names the stored value; nothing to restore"
	}
	return strings.Join(parts, "; ")
}
