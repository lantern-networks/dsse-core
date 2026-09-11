package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// "I have confirmed this identity holds that anchor, by other means."
//
// Adoption is measured from what devices REPORT, which is right for anything running the steering agent and
// impossible for anything that is not. A connector is enrolled because it needs an identity, verifies the Edge
// against a CA FILE an operator controls, and reports nothing — so it can never appear as ready, the figure can
// never reach every device, and the gate that guards a fleet-wide anchor withdrawal can never open. A gate that
// cannot open is not a safeguard; it is an instruction to ignore the safeguard.
//
// The temptation is to drop such identities from the denominator. That would be a fix that silences a correct
// warning: nothing about being unable to report means being safe, and a device that genuinely should have
// reported would vanish into the same silence.
//
// So the operator answers instead, per identity and per anchor, and the answer is recorded with who said it and
// why. It is not "ignore this" — it is a statement of fact about a deployment the operator can see and the Edge
// cannot: the connector's CA file has been updated. An assertion that turns out to be wrong strands that
// connector, which is exactly the accountability an assertion should carry.
type transportAnchorAcknowledgements struct {
	mu   sync.RWMutex
	by   map[string]transportAnchorAcknowledgement // key: sha256 + "\x00" + identity
	path string
	// shared is the deployment's own database, used INSTEAD of path on a node that AUTHORS.
	//
	// ★★★ AN ASSERTION HAS TO OUTLIVE THE MACHINE THAT TOOK IT (2026-09-07). These are the judgements that
	// OPEN a withdrawal, they are made through the Console against the leading control plane, and leadership
	// moves. Kept on one node's disk, an operator's assertion disappears the moment another node takes over —
	// and a withdrawal that was already vouched for is silently refused again, with nothing saying an
	// assertion was ever made. No observation brings these back; they are the one kind of record on this
	// deployment that cannot be recomputed.
	shared blobstore.Persister
}

type transportAnchorAcknowledgement struct {
	SHA256         string `json:"sha256"`
	Identity       string `json:"identity"`
	Reason         string `json:"reason"`
	AcknowledgedBy string `json:"acknowledged_by"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

// transportAnchorAcks is the process-wide store. A package-level value because the anchors endpoint and the
// admin routes that write it are registered from different places and must see the same assertions.
var transportAnchorAcks = newTransportAnchorAcknowledgements("")

const transportAnchorAckSchemaVersion = "admin_transport_anchor_ack.v1"

type transportAnchorAckState struct {
	SchemaVersion    string                           `json:"schema_version"`
	Acknowledgements []transportAnchorAcknowledgement `json:"acknowledgements"`
}

func ackKey(sha256Hex, identity string) string {
	return strings.ToLower(strings.TrimSpace(sha256Hex)) + "\x00" + strings.ToLower(strings.TrimSpace(identity))
}

func newTransportAnchorAcknowledgements(path string) *transportAnchorAcknowledgements {
	a := &transportAnchorAcknowledgements{by: map[string]transportAnchorAcknowledgement{}, path: strings.TrimSpace(path)}
	a.load()
	return a
}

// newSharedTransportAnchorAcknowledgements keeps the same assertions in the deployment's database, so the
// node that judges a withdrawal reads the ones an operator made against whichever node was leading then.
func newSharedTransportAnchorAcknowledgements(shared blobstore.Persister) *transportAnchorAcknowledgements {
	a := &transportAnchorAcknowledgements{by: map[string]transportAnchorAcknowledgement{}, shared: shared}
	a.load()
	return a
}

// where names the store in a message, so a refusal says which one it is talking about.
func (a *transportAnchorAcknowledgements) where() string {
	if a.shared != nil {
		return "the deployment's shared store"
	}
	return a.path
}

func (a *transportAnchorAcknowledgements) load() {
	if a == nil || (a.path == "" && a.shared == nil) {
		return
	}
	var raw []byte
	var err error
	if a.shared != nil {
		raw, err = a.shared.Load()
		if err == nil && len(raw) == 0 {
			return
		}
	} else {
		raw, err = os.ReadFile(a.path)
	}
	if err != nil {
		// Not there yet is the ordinary first run and says nothing. Anything else is a store this node was
		// given and could not read, and these are OPERATOR ASSERTIONS — judgements somebody made once, which
		// no observation will bring back. A withdrawal that was already vouched for silently goes back to
		// being refused.
		if !os.IsNotExist(err) {
			log.Printf("★ transport anchor acknowledgements: %s could not be read (%v) — an operator's "+
				"assertions that a device holds an anchor by other means are NOT loaded, so a retirement they "+
				"vouched for will be refused again", a.path, err)
		}
		return
	}
	var state transportAnchorAckState
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("★ transport anchor acknowledgements: %s did not parse (%v) — starting with none rather "+
			"than half a set, and the assertions in it are not in effect", a.where(), err)
		return
	}
	a.mu.Lock()
	for _, ack := range state.Acknowledgements {
		a.by[ackKey(ack.SHA256, ack.Identity)] = ack
	}
	loaded := len(a.by)
	a.mu.Unlock()
	if loaded > 0 {
		log.Printf("transport anchor acknowledgements: %d operator assertion(s) loaded from %s", loaded, a.where())
	}
}

func (a *transportAnchorAcknowledgements) persistLocked() error {
	if a.path == "" && a.shared == nil {
		return nil
	}
	out := make([]transportAnchorAcknowledgement, 0, len(a.by))
	for _, ack := range a.by {
		out = append(out, ack)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SHA256 != out[j].SHA256 {
			return out[i].SHA256 < out[j].SHA256
		}
		return out[i].Identity < out[j].Identity
	})
	raw, err := json.Marshal(transportAnchorAckState{SchemaVersion: transportAnchorAckSchemaVersion, Acknowledgements: out})
	if err != nil {
		return err
	}
	if a.shared != nil {
		return a.shared.Save(raw)
	}
	if dir := filepath.Dir(a.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(a.path, raw, 0o600)
}

// Acknowledge records the operator's assertion. Durable: losing it on restart would re-close a gate an operator
// had deliberately opened, and they would have no way to tell why.
func (a *transportAnchorAcknowledgements) Acknowledge(sha256Hex, identity, reason, by string, now time.Time) error {
	if a == nil {
		return fmt.Errorf("acknowledgements are not configured")
	}
	if strings.TrimSpace(sha256Hex) == "" || strings.TrimSpace(identity) == "" {
		return fmt.Errorf("both an anchor fingerprint and an identity are required")
	}
	if strings.TrimSpace(by) == "" {
		// An unattributed assertion is not an assertion. Somebody is claiming a fact about a deployment; the
		// record has to say who, or it cannot be revisited when the claim turns out to be wrong.
		return fmt.Errorf("the acknowledging administrator is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.by[ackKey(sha256Hex, identity)] = transportAnchorAcknowledgement{
		SHA256: strings.ToLower(strings.TrimSpace(sha256Hex)), Identity: strings.TrimSpace(identity),
		Reason: strings.TrimSpace(reason), AcknowledgedBy: strings.TrimSpace(by),
		AcknowledgedAt: now.UTC().Format(time.RFC3339),
	}
	return a.persistLocked()
}

func (a *transportAnchorAcknowledgements) Withdraw(sha256Hex, identity string) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.by, ackKey(sha256Hex, identity))
	return a.persistLocked()
}

// For returns the acknowledged identities for one anchor.
func (a *transportAnchorAcknowledgements) For(sha256Hex string) []transportAnchorAcknowledgement {
	if a == nil {
		return nil
	}
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []transportAnchorAcknowledgement{}
	for _, ack := range a.by {
		if strings.ToLower(ack.SHA256) == want {
			out = append(out, ack)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// applyAnchorAcknowledgements moves acknowledged identities out of the not-yet-ready lists so the safe-to-cut
// decision can be reached, WITHOUT pretending they reported.
//
// They are removed from silent/not-ready rather than added to ready, and the percentage counts them, so an
// operator reading the lists still sees exactly who said what. Ready means "the device told us"; the
// acknowledged list means "somebody vouched for it". A screen that merged them would answer "is this safe" and
// destroy "how do we know".
// known is the enrolled set the readiness was measured over: an acknowledgement counts only for an
// identity that is actually in it.
func applyAnchorAcknowledgements(r transportCAReadiness, acknowledged map[string]bool, known []string) transportCAReadiness {
	if len(acknowledged) == 0 {
		return r
	}
	keep := func(list []string) []string {
		out := []string{}
		for _, id := range list {
			if !acknowledged[strings.ToLower(strings.TrimSpace(id))] {
				out = append(out, id)
			}
		}
		return out
	}
	r.NotReady = keep(r.NotReady)
	r.Silent = keep(r.Silent)
	r.NeverReportedAnything = keep(r.NeverReportedAnything)

	// Only assertions about identities the measurement is ABOUT may move the measurement. Counting every
	// acknowledgement would let one vouch for a name that does not exist pad the denominator until the gate
	// opens — an assertion about nobody is not evidence about the fleet (review R4). Verified by probe: a
	// single ack of an unknown string took an empty readiness from 0% to 100% and safe_to_cut to true.
	counted := 0
	for _, id := range known {
		if acknowledged[strings.ToLower(strings.TrimSpace(id))] {
			counted++
		}
	}
	total := len(r.Ready) + len(r.NotReady) + len(r.Silent) + counted
	if total > 0 {
		r.ReadyPct = (len(r.Ready) + counted) * 100 / total
	}
	// Still all-or-nothing: everything is either reported ready or vouched for. "Almost all" remains the state
	// in which a changeover creates the cases that need a person. An empty denominator is not consent: with no
	// enrolled device to measure, there is nothing to be safe about and the gate stays shut.
	r.SafeToCut = total > 0 && len(r.NotReady) == 0 && len(r.Silent) == 0
	return r
}
