package revocation

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// AdmissionRevocations is the dynamic overlay on top of the static Enrolled Inventory: a thread-safe set of
// transport identities the Edge has AUTO-revoked (e.g. an agent-dark device). The (T) mTLS admission check
// consults it so a revoked identity is rejected at the handshake even though it is still present in the
// (static) enrolled file. Restore clears a locally authored block. It does not
// withdraw a received-region or pulled block; enrollment alone is not a mesh restore.
//
// Keyed on the TRANSPORT IDENTITY (the cert CN/SAN that admission matches), not the device store id; the
// wiring layer maps a dark device to its transport identity before calling Revoke.
//
// Phase 3 (shared revocation overlay): the overlay now has TWO layers — `revoked` (node-LOCAL: this Edge's
// admin kill-switches + its own W-2 auto-revocations) and `synced` (the control plane's revocation set,
// pulled fast and applied via ReplaceSynced). IsRevoked denies if an identity is in EITHER, so a device
// revoked on the CP is refused on EVERY node (reconnect-to-evade blocked) while a node's own auto-revocation
// still bites locally. The CP serves its `revoked` set as the feed; persistence keeps it across a CP restart
// (a restart must NOT silently un-revoke). generation is bumped on every node-local change for the feed.
type AdmissionRevocations struct {
	// Persisted-layer writers and persister replacement serialize here. Readers
	// and the independently pulled synced layer never wait for storage I/O.
	// Lock order: writeMu, then mu. No callback runs under either lock.
	writeMu sync.Mutex
	mu      sync.RWMutex
	revoked map[string]string // node-local / ORIGIN: this region's admin kill-switches + its own W-2 auto-revocations
	synced  map[string]string // control-plane distributed (Phase 3, intra-region): identity -> reason
	// meshReceived is the federation layer: revocations PUSHED here by an external peer (e.g. a sibling control
	// plane). They deny on this node's edges (folded into the edge feed) but are NEVER re-pushed — only an ORIGIN
	// pushes, so a received item does not bounce back (the no-loop discipline).
	meshInitialPending bool // writeMu: first shared save ran its edit but was unconfirmed
	meshReceived       map[string]string
	persister          blobstore.Persister // guarded by writeMu; snapshot of revoked + meshReceived; nil = volatile
	generation         atomic.Uint64       // bumped on any state change; the CP serves it in the feed so edges re-pull
	// reporter, when set (puller mode), is called on a NEW node-local revocation so this node's own W-2
	// auto-revocation propagates UP to the control plane, which redistributes it fleet-wide (slice 3b: a dark
	// device caught on one node is then denied on every node, not just this one). Not called for ReplaceSynced.
	reporter func(identity, reason string)
	// meshReporter, when set (a CP that federates with peers), is called on a NEW ORIGIN revocation so it
	// propagates to the federation peers. NOT called for a federation-RECEIVED item (no-loop) nor for
	// ReplaceSynced.
	meshReporter func(context.Context, string, string)
	// onRevoked, when set, is called ONCE when an identity BECOMES revoked via ANY layer (node-local Revoke,
	// federation RevokeFromMesh, or a NEWLY-added entry in ReplaceSynced) — i.e. it fires on the fast CP poll
	// too, unlike reporter/meshReporter. It exists so the edge can ACTIVELY close that identity's live (T)
	// connections: per-handshake admission already rejects NEW connections, but an already-established tunnel
	// is not re-checked, so a kill-switch must also tear down established sessions. Fired outside the lock.
	onRevoked func(identity, reason string)
}

func NewAdmissionRevocations() *AdmissionRevocations {
	return &AdmissionRevocations{revoked: map[string]string{}, synced: map[string]string{}, meshReceived: map[string]string{}}
}

// SetReporter wires the node→CP propagation hook (puller mode). Called once at boot.
func (a *AdmissionRevocations) SetReporter(reporter func(identity, reason string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reporter = reporter
}

// SetMeshReporter wires the federation propagation hook: a CP calls this so a NEW ORIGIN revocation is pushed to
// its federation peers. Called once at boot.
func (a *AdmissionRevocations) SetMeshReporter(reporter func(identity, reason string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if reporter == nil {
		a.meshReporter = nil
	} else {
		a.meshReporter = func(_ context.Context, id, reason string) { reporter(id, reason) }
	}
}

// SetMeshReporterContext preserves the revocation request authority for its outbox.
func (a *AdmissionRevocations) SetMeshReporterContext(reporter func(context.Context, string, string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.meshReporter = reporter
}

// SetOnRevoked wires the become-revoked hook (see the field doc). Called once at boot. The edge uses it to
// actively close a revoked identity's live (T) connections so the kill-switch bites established sessions too.
func (a *AdmissionRevocations) SetOnRevoked(fn func(identity, reason string)) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onRevoked = fn
}

// RevokeFromMesh folds a revocation PUSHED from a peer region's CP into the cross-region layer. It denies on this
// region's edges (via the feed) but is never re-pushed cross-region (no-loop). Monotonic: only a state change
// bumps the generation + persists, so re-delivering the same item is a no-op. Returns whether it changed state.
func (a *AdmissionRevocations) RevokeFromMesh(identity, reason string) bool {
	changed, _ := a.revokeFromMesh(identity, reason, false)
	return changed
}

// RevokeFromMeshChecked retains the received block even when saving fails. Each
// explicit delivery retries saving, including an unchanged item, so the receiver
// acknowledges delivery only after the configured store accepts the snapshot.
// Unchanged retries do not bump generation, invoke callbacks or re-push the item.
func (a *AdmissionRevocations) RevokeFromMeshChecked(identity, reason string) (bool, error) {
	return a.RevokeFromMeshCheckedContext(context.Background(), identity, reason)
}

func (a *AdmissionRevocations) revokeFromMesh(identity, reason string, retrySave bool) (bool, error) {
	id := normalizeIdentity(identity)
	if id == "" {
		return false, nil
	}
	reason = strings.TrimSpace(reason)
	a.writeMu.Lock()
	a.mu.Lock()
	prev, existed := a.meshReceived[id]
	changed := !existed || prev != reason
	if changed {
		a.meshReceived[id] = reason
		a.generation.Add(1)
	}
	a.mu.Unlock()
	var err error
	if changed || retrySave {
		err = a.persistLocked()
	}
	a.mu.RLock()
	onRevoked := a.onRevoked
	a.mu.RUnlock()
	a.writeMu.Unlock()
	if changed && onRevoked != nil {
		onRevoked(id, reason)
	}
	return changed, err
}

// ConfigGeneration returns the monotonic revocation version (bumped on each node-local change). The control
// plane serves it in GET /admin/revocations; a puller's fast poller applies on a newer generation / new epoch.
func (a *AdmissionRevocations) ConfigGeneration() uint64 {
	if a == nil {
		return 0
	}
	return a.generation.Load()
}

// Snapshot returns a copy of this Edge's node-local revocation set — the payload the control plane ships in
// the revocation feed (its admin kill-switches + its own auto-revocations).
func (a *AdmissionRevocations) Snapshot() map[string]string {
	out := map[string]string{}
	if a == nil {
		return out
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for k, v := range a.revoked {
		out[k] = v
	}
	return out
}

// ReplaceSynced atomically replaces the control-plane-distributed revocation layer (Phase 3). Node-local
// `revoked` entries are untouched. Identities are normalized.
func (a *AdmissionRevocations) ReplaceSynced(synced map[string]string) {
	if a == nil {
		return
	}
	fresh := make(map[string]string, len(synced))
	for k, v := range synced {
		if id := normalizeIdentity(k); id != "" {
			fresh[id] = strings.TrimSpace(v)
		}
	}
	a.mu.Lock()
	onRevoked := a.onRevoked
	var newly [][2]string // (identity, reason) that became revoked this replace — fired after unlock
	if onRevoked != nil {
		for id, reason := range fresh {
			// Newly revoked only: not already denied by any layer, so the fast CP poll doesn't re-fire the
			// whole set every interval (it re-closes nothing; this just keeps it quiet + O(new)).
			if _, ok := a.synced[id]; ok {
				continue
			}
			if _, ok := a.revoked[id]; ok {
				continue
			}
			if _, ok := a.meshReceived[id]; ok {
				continue
			}
			newly = append(newly, [2]string{id, reason})
		}
	}
	a.synced = fresh
	a.mu.Unlock()
	for _, n := range newly {
		onRevoked(n[0], n[1])
	}
}

func normalizeIdentity(identity string) string {
	return strings.ToLower(strings.TrimSpace(identity))
}

// Revoke marks an identity as revoked (node-local). Idempotent. Empty identity is ignored (never revoke
// "nothing"). Only a STATE CHANGE bumps the generation + persists + reports (so a repeated W-2 sweep doesn't
// churn the feed or spam the control plane). On a new revocation the reporter (puller mode) ships it UP to the
// control plane for fleet-wide redistribution.
func (a *AdmissionRevocations) Revoke(identity, reason string) {
	_ = a.revoke(identity, reason, false)
}

// RevokeChecked applies the restrictive local decision even if saving fails.
// An error means persistence is unconfirmed, not that the block was rolled back.
// Explicit retries save an unchanged block again without repeating callbacks or
// bumping its generation. Automatic Revoke retains its no-churn behaviour.
func (a *AdmissionRevocations) RevokeChecked(identity, reason string) error {
	return a.revoke(identity, reason, true)
}

func (a *AdmissionRevocations) revoke(identity, reason string, retrySave bool) error {
	return a.revokeContext(context.Background(), identity, reason, retrySave)
}
func (a *AdmissionRevocations) revokeContext(ctx context.Context, identity, reason string, retrySave bool) error {
	id := normalizeIdentity(identity)
	if id == "" {
		return nil
	}
	reason = strings.TrimSpace(reason)
	a.writeMu.Lock()
	a.mu.Lock()
	prev, existed := a.revoked[id]
	changed := !existed || prev != reason
	if changed {
		a.revoked[id] = reason
		a.generation.Add(1)
	}
	a.mu.Unlock()
	var err error
	if changed || retrySave {
		err = a.persistLocked()
	}
	a.mu.RLock()
	reporter := a.reporter
	meshReporter := a.meshReporter
	onRevoked := a.onRevoked
	a.mu.RUnlock()
	a.writeMu.Unlock()
	if changed && reporter != nil {
		reporter(id, reason)
	}
	// Federation push: an ORIGIN revocation propagates to the federation peers. Only fired for an origin Revoke —
	// a federation-RECEIVED item (RevokeFromMesh) never re-pushes (no-loop).
	if changed && meshReporter != nil {
		meshReporter(ctx, id, reason)
	}
	// Active session revocation: close the identity's live connections (idempotent no-op if none).
	if changed && onRevoked != nil {
		onRevoked(id, reason)
	}
	return err
}

// Restore clears a node-local revocation (re-admission after re-enroll/re-attest). Idempotent — only a real
// removal bumps the generation + persists. A CP-distributed (synced) revocation can only be cleared at the
// control plane.
func (a *AdmissionRevocations) Restore(identity string) {
	_ = a.restore(identity, false)
}

// RestoreChecked saves before lifting a local block. Failed or unconfirmed
// persistence leaves the live block and generation unchanged. Storage might have
// accepted bytes before returning an error: reconcile and explicitly retry before
// restarting. Neither restore method clears synced or mesh revocations.
func (a *AdmissionRevocations) RestoreChecked(identity string) error {
	return a.restore(identity, true)
}

func (a *AdmissionRevocations) restore(identity string, retrySave bool) error {
	id := normalizeIdentity(identity)
	if id == "" {
		return nil
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	a.mu.RLock()
	_, existed := a.revoked[id]
	if !existed && !retrySave {
		a.mu.RUnlock()
		return nil
	}
	candidate := make(map[string]string, len(a.revoked))
	for key, reason := range a.revoked {
		if key != id {
			candidate[key] = reason
		}
	}
	a.mu.RUnlock()
	if err := a.saveStateLocked(candidate); err != nil {
		return err
	}
	if existed {
		a.mu.Lock()
		a.revoked = candidate
		a.generation.Add(1)
		a.mu.Unlock()
	}
	return nil
}

// IsRevoked reports whether an identity is currently revoked (node-local OR control-plane distributed), with
// its reason. Either layer denies — that is the shared-revocation invariant (revoke on the CP => denied on
// every node).
func (a *AdmissionRevocations) IsRevoked(identity string) (string, bool) {
	if a == nil {
		return "", false
	}
	id := normalizeIdentity(identity)
	a.mu.RLock()
	defer a.mu.RUnlock()
	if reason, ok := a.revoked[id]; ok {
		return reason, true
	}
	if reason, ok := a.synced[id]; ok {
		return reason, true
	}
	if reason, ok := a.meshReceived[id]; ok {
		return reason, true
	}
	return "", false
}

// FeedSnapshot is the set this region's CP serves to ITS edges: origin revocations UNIONED with cross-region
// mesh-received ones, so a device revoked in a peer region is denied on this region's edges too. (Snapshot stays
// origin-only — the cross-region push is per-item via the mesh reporter, not the feed.)
func (a *AdmissionRevocations) FeedSnapshot() map[string]string {
	out := map[string]string{}
	if a == nil {
		return out
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for k, v := range a.revoked {
		out[k] = v
	}
	for k, v := range a.meshReceived {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// SyncedCount returns the number of CP-distributed (synced-layer) revocations currently held. The revocation
// sync layer uses it for a lockout-safe guard: if the control plane sends ZERO revocations while this Edge still
// holds some, that is more likely a CP blip / empty-response than a deliberate fleet-wide clear, so the sync
// keeps the local set rather than silently un-revoking everyone.
func (a *AdmissionRevocations) SyncedCount() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.synced)
}

// List returns a sorted snapshot of ALL revoked identities (node-local + CP-distributed) for the
// admin/observability surface.
func (a *AdmissionRevocations) List() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	set := map[string]struct{}{}
	for id := range a.revoked {
		set[id] = struct{}{}
	}
	for id := range a.synced {
		set[id] = struct{}{}
	}
	for id := range a.meshReceived {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// admitDecision is the PURE combination of the static Enrolled Inventory and the W-2 revocation overlay for
// one transport identity. revoked is a snapshot set; requireEnrolled mirrors cfg.RequireEnrolledIdentity.
// Returns (admit, non-secret reason code). Auto-revocation WINS over enrolment: a revoked identity is denied
// even if it is still in the enrolled file (that is the whole point — disabling the file edit is not how you
// un-revoke; local restore handles the locally authored layer). Reason codes mirror
// the live handshake log vocabulary.
func admitDecision(enrolled map[string]struct{}, revoked map[string]struct{}, requireEnrolled bool, identity string) (bool, string) {
	id := normalizeIdentity(identity)
	if _, gone := revoked[id]; gone && id != "" {
		return false, "revoked"
	}
	if requireEnrolled {
		if id == "" {
			return false, "no_identity"
		}
		if _, ok := enrolled[id]; !ok {
			return false, "not_enrolled"
		}
	}
	return true, ""
}

// CountDevices returns how many of the named identities this node currently refuses admission to (its own
// kill-switches). Keyed by identity, so the caller resolves attribution from the enrolled ledger.
func (a *AdmissionRevocations) CountDevices(deviceIDs []string) int {
	if a == nil || len(deviceIDs) == 0 {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := 0
	for _, id := range deviceIDs {
		if _, ok := a.revoked[NormalizeDeviceID(id)]; ok {
			n++
		}
	}
	return n
}

// RemoveDevices clears this node's own kill-switches for the named identities, returning how many went.
//
// Only the ORIGIN set: a revocation this node RECEIVED from a peer is that peer's record, and erasing it here
// would take a denial off this node's edges while the peer still publishes it — the two would then disagree
// about a device nobody can see any more. The caller's own set is the caller's to erase.
//
// ★ The ids must be captured BEFORE the enrolled ledger is cleared, or this receives an empty list and removes
// nothing, which reads identically to "there were none".
func (a *AdmissionRevocations) RemoveDevices(deviceIDs []string) int {
	n, _ := a.RemoveDevicesChecked(deviceIDs)
	return n
}

// RemoveDevicesChecked publishes origin erasure only after saving. Explicit
// retries also resave an unchanged candidate after an ambiguous storage outcome.
// Received and pulled revocations are not owned by this operation.
func (a *AdmissionRevocations) RemoveDevicesChecked(deviceIDs []string) (int, error) {
	if a == nil || len(deviceIDs) == 0 {
		return 0, nil
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	a.mu.RLock()
	candidate := make(map[string]string, len(a.revoked))
	for id, reason := range a.revoked {
		candidate[id] = reason
	}
	a.mu.RUnlock()
	n := 0
	for _, id := range deviceIDs {
		key := NormalizeDeviceID(id)
		if _, ok := candidate[key]; ok {
			delete(candidate, key)
			n++
		}
	}
	if err := a.saveStateLocked(candidate); err != nil {
		return 0, err
	}
	if n > 0 {
		a.mu.Lock()
		a.revoked = candidate
		a.generation.Add(1)
		a.mu.Unlock()
	}
	return n, nil
}
