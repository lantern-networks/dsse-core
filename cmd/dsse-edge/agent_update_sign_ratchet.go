package main

// agent_update_sign_ratchet.go — the control plane will not sign a release older than one it has already
// signed for the same target.
//
// ★ WHY THIS EXISTS (2026-08-13, docs/2026-08-13_agent_publish_authority_design.ja.md, in place of two-person
// approval). Once the update key is in the HSM and the CP signs on request, a compromised control plane can
// still ask for a signature. The highest-value thing it could ask for is a DOWNGRADE: an old release, genuinely
// built and signed by this publisher, whose vulnerabilities are public. Publisher verification on the device
// cannot stop that — those really are our bytes. This can, and it costs an operator nothing.
//
// ★ EQUAL VERSIONS ARE ALLOWED, AND THE DESIGN SKETCH SAID "NEWER ONLY" (corrected here). A manifest EXPIRES,
// so re-signing the same version is a routine, necessary act; a strict ratchet would make every release
// permanently unpublishable a few weeks after it shipped, and the operator's only escape would be to bump a
// version number for a build nobody changed. Re-signing the same version enables no downgrade — it is the same
// code — so the rule is: never OLDER.
//
// ★ AND IT DOES NOT BLOCK ROLLBACK. A device rolls back to a package it already holds, authorised by a local
// intent file, with no manifest involved (ExecuteRollback). Refusing to SIGN an old version therefore takes
// nothing away from the recovery path an incident actually uses.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/durablefile"
)

// agentUpdateSignRatchet remembers the highest version ever SIGNED for each (tenant, platform, arch).
//
// restart-durability: edge_durable — persisted to <state-dir>/agent_update_sign_floor.json, written durably
// (temp → fsync → rename → fsync dir) and loaded at startup, where a read error is FATAL. The control plane
// does not own it because the control plane is the party it constrains: a floor fetched from the thing being
// guarded is not a guard. It is also the only store here whose loss is silently permissive — an empty floor
// permits the downgrade — which is why a missing file is a clean start and an unreadable one stops the process.
//
// populated-by: assertion — every successful publication of a release records its version here (both doors:
// the POST that signs and the PUT that takes an envelope signed elsewhere). It is empty on a control plane
// that has never published, which is the correct floor for one.
//
// Signed, not published. A withdrawn release must not lower the floor: withdrawing is exactly what an attacker
// who wanted to re-sign an old version would do first.
type agentUpdateSignRatchet struct {
	mu   sync.Mutex
	path string
	high map[string]string // tenantTargetKey -> version string
}

func newAgentUpdateSignRatchet(stateDir string) *agentUpdateSignRatchet {
	r := &agentUpdateSignRatchet{high: map[string]string{}}
	if d := strings.TrimSpace(stateDir); d != "" {
		r.path = filepath.Join(d, "agent_update_sign_floor.json")
	}
	return r
}

// Load reads the floor from disk. A missing file is a clean start; anything else is an error, because a
// ratchet that silently forgets its floor is not a ratchet.
func (r *agentUpdateSignRatchet) Load() error {
	if r == nil || r.path == "" {
		return nil
	}
	raw, err := os.ReadFile(r.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the update-signing floor %s: %w", r.path, err)
	}
	var on map[string]string
	if err := json.Unmarshal(raw, &on); err != nil {
		return fmt.Errorf("the update-signing floor %s is not valid JSON: %w", r.path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range on {
		r.high[k] = v
	}
	return nil
}

// Check answers whether this version may be signed, without recording anything.
func (r *agentUpdateSignRatchet) Check(tenantID, platform, arch, version string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	floor := r.high[tenantTargetKey(tenantID, platform, arch)]
	r.mu.Unlock()
	return compareToFloor(floor, version, platform, arch)
}

func compareToFloor(floor, version, platform, arch string) error {
	if strings.TrimSpace(floor) == "" {
		return nil
	}
	want, werr := agentupdate.ParseVersion(version)
	have, herr := agentupdate.ParseVersion(floor)
	if werr != nil || herr != nil {
		// ★ UNPARSEABLE MUST NOT MEAN UNRESTRICTED. Whichever side is malformed, the comparison did not happen,
		// and the whole value of a ratchet is that it is not optional. The floor is recorded by this process from
		// versions it already validated, so a malformed floor means the file was edited or corrupted — which is
		// precisely the state in which signing should stop.
		return fmt.Errorf("this control plane will not sign %s for %s/%s: the signing floor for that target is %q "+
			"and the two cannot be compared (%v/%v) — a downgrade guard that cannot run must not pass",
			version, platform, arch, floor, werr, herr)
	}
	if agentupdate.CompareVersions(want, have) < 0 {
		return fmt.Errorf("this control plane has already signed %s for %s/%s and will not sign the older %s: a "+
			"downgrade to a build whose weaknesses are public is the most valuable thing a compromised control "+
			"plane could ask for, and it is the one thing device-side publisher verification cannot refuse — those "+
			"really are this publisher's bytes. Roll back instead: a device reinstalls the package it already "+
			"holds, which needs no manifest", have, platform, arch, want)
	}
	return nil
}

// Record raises the floor and persists it. It is called AFTER a successful signature, so a crash between
// signing and recording leaves the floor low rather than high — the direction that loses a guard for one
// version rather than locking an operator out of a target they never signed.
func (r *agentUpdateSignRatchet) Record(tenantID, platform, arch, version string) error {
	if r == nil {
		return nil
	}
	key := tenantTargetKey(tenantID, platform, arch)
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.high[key]
	if cur != "" {
		a, aerr := agentupdate.ParseVersion(version)
		b, berr := agentupdate.ParseVersion(cur)
		if aerr == nil && berr == nil && agentupdate.CompareVersions(a, b) <= 0 {
			return nil // an equal or lower version does not lower the floor
		}
	}
	r.high[key] = version
	if r.path == "" {
		return nil
	}
	body, err := json.MarshalIndent(sortedCopy(r.high), "", "  ")
	if err != nil {
		return err
	}
	// ★ THROUGH THE SHARED PACKAGE, AND THE HAND-WRITTEN COPY THAT WAS HERE IS WHY IT EXISTS (2026-08-13). This
	// file originally carried its own temp-fsync-rename-fsyncdir helper, with a comment explaining that the
	// neighbours' versions were unexported so it was written rather than borrowed. It ended in os.Open(dir) +
	// Sync, which on Windows does not degrade — it FAILS, every time — so every Record failed, the floor
	// never rose, and the downgrade guard this file exists for was off on that platform. Found by the Windows
	// gate within the hour. Four copies of one shape had by then produced three instances of one bug, so the
	// shape is now a package and ops/checks refuses a fifth copy.
	return durablefile.Write(r.path, append(body, '\n'), 0o600)
}

// FloorsForTenant is the operator-facing view: what this control plane will not sign below, for the caller's
// own tenant.
//
// ★ IT USED TO RETURN EVERY TENANT'S (2026-08-13, thirtieth review #15). The map is keyed
// "<tenant>|<platform>/<arch>", and returning it whole let any tenant-scoped administrator read which targets
// another tenant ships and the highest version it has signed — a release history, from a screen about their
// own fleet. Every other route in this lane scopes by adminTenantIDFromRequest; this one was written last and
// did not.
//
// The tenant prefix is stripped on the way out too: a key naming another tenant would be the same disclosure in
// a smaller font, and the caller already knows which tenant they are.
func (r *agentUpdateSignRatchet) FloorsForTenant(tenantID string) map[string]string {
	out := map[string]string{}
	if r == nil {
		return out
	}
	prefix := strings.ToLower(strings.TrimSpace(tenantID)) + "|"
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.high {
		if target, ok := strings.CutPrefix(k, prefix); ok {
			out[target] = v
		}
	}
	return out
}

func sortedCopy(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = in[k]
	}
	return out
}
