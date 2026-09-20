package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"io"
	"net/url"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// admin_agent_update_publish.go — which release a FLEET is offered, owned by the control plane.
//
// ★ WHY THIS EXISTS (2026-08-11). The published manifests were a directory on each Edge, read ONCE at startup.
// Two consequences, and the second is the serious one:
//
//   - publishing required restarting the Edge. Every publication in this lab did, which is a restart per
//     release per node, on the component carrying live traffic.
//   - two Edges could offer DIFFERENT releases to the same fleet, with nothing comparing them. That is the
//     per-edge authored-rules defect (project_authored_rules_were_per_edge_not_fleet) landing on the one
//     document that decides which code runs on every managed machine.
//
// So the control plane holds the published set, durably, and enforcing Edges PULL it — the same lane as the
// halt, the config bundle and the steer exclusions.
//
// ★ THE CONTROL PLANE STILL DOES NOT SIGN. It stores an envelope somebody else signed, and it VERIFIES that
// envelope against the same pinned key an Edge would use before accepting it. Nothing about the authority to
// run code moves here: what moves is the answer to "which signed document is current", which is exactly the
// thing that must not differ between two nodes.

// maxPublishedSetBytes and maxPublishedTargets bound what a control plane may hand an Edge. A fleet publishes
// one release per platform/arch; anything approaching these is not a release set.
const (
	maxPublishedSetBytes = 4 << 20 // 4 MiB of JSON envelopes
	maxPublishedTargets  = 64
)

// publishedAgentUpdateStore is the control plane's durable set of published manifests, keyed
// TENANT/platform/arch.
//
// ★ THE TENANT IS PART OF THE KEY (2026-08-12, fifth review). It was platform/arch alone, and the endpoint is
// authorised with admin.agents.write — a role a TENANT administrator can hold. So one customer's admin could
// change which release every other customer's fleet is offered, or re-present an older signed build to all of
// them. Verifying the signature bounds that to code somebody legitimately signed; it does nothing about
// choosing WHICH signed code a different tenant runs, or about stopping their rollout entirely.
//
// restart-durability: edge_durable — this is the CONTROL PLANE's own store, so there is nowhere further up to
// fetch it from: it is persisted here through the same -state-dir guard every other operator-config store uses,
// and rehydrated at startup. Losing it would mean answering "nothing published" to a fleet after a restart,
// which is why an unreadable file stops the process instead.
//
// populated-by: assertion — an admin PUT is the only thing that fills it, and it stays filled: nothing expires
// or garbage-collects a published release. A control plane that has never been published to answers "nothing
// published", which is the true statement about a fleet nobody has released a build to.
type publishedAgentUpdateStore struct {
	mu   sync.RWMutex
	path string
	// blob is the SHARED store, when this deployment has one.
	//
	// ★★★ THE PUBLISHED SET WAS PER NODE, IN AN HA PAIR (2026-08-28, measured). region-a's control plane held
	// the catalogue and region-b's had no file at all — it never received the publish, and it loads its own
	// disk at start-up. The front door balances both, so an Edge polling every minute was answered 1 target,
	// then 0, then 1: every device read "nothing published" every other minute, and the Edge said so, loudly
	// and correctly, about a control plane that was simply the other one.
	//
	// Third instance of one shape in a day — the transport, device-identity and interception authorities each
	// had it — and the same answer: the set an operator publishes is the deployment's, so it lives where the
	// deployment's state lives.
	blob blobstore.Persister
	// envelopes is the ACTIVE set: releases whose bytes this control plane can already hand over.
	envelopes map[string]agentpolicy.Envelope
	// pending holds a published manifest whose artifact has NOT arrived yet.
	//
	// ★ A MANIFEST WITHOUT ITS BYTES IS NOT A RELEASE (2026-08-12, fifth review). Publishing replaced the
	// active entry immediately, so between the manifest PUT and the artifact PUT — and for as long as an
	// upload was retried — the control plane offered a version whose bytes answered 404. The ordering cannot
	// be reversed (bytes are only checkable against a manifest that names their digest), so the manifest is
	// accepted and held PENDING, and the artifact upload is what activates it. Until then the fleet keeps
	// being offered the release that can actually be served.
	pending map[string]agentpolicy.Envelope
	// legacy holds pre-tenant entries, read-only. See LoadFrom.
	legacy map[string]agentpolicy.Envelope
	// artifactDir is where the BYTES of what is published live, so that removing an organization can remove
	// the builds published to it and not only the documents naming them.
	artifactDir string
	// shelf is the deployment's shared shelf for those bytes.
	//
	// ★★★ THE DOCUMENTS TRAVELLED AND THE BYTES DID NOT (2026-08-28, measured on the two-region lab: four
	// control-plane containers, four different sets of .pkg files, one of them empty). Sharing the manifests
	// alone would have made the catalogue agree everywhere and the DOWNLOAD fail on whichever node the front
	// door picked — a release the whole fleet can see and half the fleet cannot fetch, which is worse than the
	// inconsistency it replaced, because the manifest is a promise that the bytes are there.
	//
	// So a release is only ACTIVE once its bytes are on the deployment's shelf, and a node that does not have
	// them locally fills from there on first ask.
	shelf *agentUpdateArtifactShelf
}

// agentUpdateArtifactShelf is where a deployment keeps release bytes so that any of its control planes can
// hand them over. open mints the store for one release; forget drops everything an organization was given,
// which is what its erasure needs and what a per-release handle cannot express.
type agentUpdateArtifactShelf struct {
	open   func(key string) blobstore.Persister
	forget func(tenantID string) error
}

// WithArtifactShelf names the shared shelf. nil leaves this node keeping bytes on its own disk, which is
// correct for a single-control-plane deployment and for every test.
func (s *publishedAgentUpdateStore) WithArtifactShelf(shelf *agentUpdateArtifactShelf) *publishedAgentUpdateStore {
	if s == nil {
		return s
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shelf = shelf
	return s
}

// artifactBlobKey names one release's bytes on the shared shelf. Empty for anything that would not be stored
// on disk either, so the two cannot disagree about what exists.
func artifactBlobKey(tenantID, platform, arch, version string) string {
	name := artifactFileName(platform, arch, version)
	t := strings.ToLower(strings.TrimSpace(tenantID))
	if name == "" || t == "" || strings.ContainsAny(t, `/\`) || strings.Contains(t, "..") {
		return ""
	}
	return artifactBlobKeyPrefix(t) + name
}

func artifactBlobKeyPrefix(tenantID string) string {
	return "agent_update_artifact|" + strings.ToLower(strings.TrimSpace(tenantID)) + "|"
}

func (s *publishedAgentUpdateStore) shelfFor(tenantID, platform, arch, version string) blobstore.Persister {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	shelf := s.shelf
	s.mu.RUnlock()
	if shelf == nil || shelf.open == nil {
		return nil
	}
	key := artifactBlobKey(tenantID, platform, arch, version)
	if key == "" {
		return nil
	}
	return shelf.open(key)
}

// shelveArtifact puts the bytes at path onto the deployment's shelf. No shelf is not an error: a deployment
// with one control plane keeps them on its disk and always could.
func (s *publishedAgentUpdateStore) shelveArtifact(path, tenantID, platform, arch, version string) error {
	blob := s.shelfFor(tenantID, platform, arch, version)
	if blob == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return blob.Save(data)
}

// SeedShelfFromDisk puts every release this node already holds the bytes of onto the deployment's shared
// shelf, and answers how many it added.
//
// ★★★ A DEPLOYMENT THAT WAS ALREADY PUBLISHING MUST NOT LOSE ITS DOWNLOADS THE DAY THE SHELF ARRIVES
// (2026-08-28). The manifests migrate through postgres+import; the bytes had nowhere to migrate through, so
// every release published before this change would have been named by both control planes and served by
// neither. Each node offers what it has, once, at start-up.
//
// ★ ONLY BYTES THAT ARE THE ONES THE PUBLISHED MANIFEST NAMES. The digest is checked before anything is
// shelved, so a node holding a stale or half-written file cannot make it the deployment's copy — which is the
// difference between a migration and a way to distribute the wrong build.
func (s *publishedAgentUpdateStore) SeedShelfFromDisk(dir string, trustedKeys []string, now time.Time) int {
	if s == nil || strings.TrimSpace(dir) == "" {
		return 0
	}
	s.mu.RLock()
	shelf := s.shelf
	active := make(map[string]agentpolicy.Envelope, len(s.envelopes))
	for k, v := range s.envelopes {
		active[k] = v
	}
	s.mu.RUnlock()
	if shelf == nil || shelf.open == nil {
		return 0
	}
	seeded := 0
	for key, env := range active {
		tenant, _, ok := strings.Cut(key, "|")
		if !ok || strings.TrimSpace(tenant) == "" {
			continue
		}
		m, oerr := agentupdate.Open(env, trustedKeys, now)
		if oerr != nil {
			continue
		}
		blob := s.shelfFor(tenant, m.Platform, m.Arch, m.Version)
		if blob == nil {
			continue
		}
		if held, lerr := blob.Load(); lerr == nil && len(held) > 0 {
			continue
		}
		path := artifactStorePath(dir, tenant, m.Platform, m.Arch, m.Version)
		if path == "" || !artifactBytesMatch(path, m) {
			continue
		}
		if serr := s.shelveArtifact(path, tenant, m.Platform, m.Arch, m.Version); serr != nil {
			log.Printf("agent_update_artifact_seed_failed tenant=%s target=%s/%s version=%s err=%v", tenant,
				m.Platform, m.Arch, m.Version, serr)
			continue
		}
		log.Printf("agent_update_artifact_seeded tenant=%s target=%s/%s version=%s — this node held the bytes "+
			"and the deployment's shelf did not, so every control plane can serve it now", tenant, m.Platform,
			m.Arch, m.Version)
		seeded++
	}
	return seeded
}

// artifactPathFor is where this node can READ a release's bytes: its own disk, and failing that the
// deployment's shelf, filled onto this disk so the next ask is a file read like any other.
func (s *publishedAgentUpdateStore) artifactPathFor(dir, tenantID, platform, arch, version string) string {
	local := artifactReadPath(dir, tenantID, platform, arch, version)
	if local != "" {
		if _, err := os.Stat(local); err == nil {
			return local
		}
	}
	// The organization's own shelf first, then the deployment's catalogue — the same order, and for the same
	// reason, as artifactReadPath.
	for _, owner := range []string{tenantID, agentUpdateCatalogueScope} {
		if filled, ok := s.fillArtifact(dir, owner, platform, arch, version); ok {
			return filled
		}
	}
	return local
}

func (s *publishedAgentUpdateStore) fillArtifact(dir, tenantID, platform, arch, version string) (string, bool) {
	blob := s.shelfFor(tenantID, platform, arch, version)
	if blob == nil {
		return "", false
	}
	path := artifactStorePath(dir, tenantID, platform, arch, version)
	if path == "" {
		return "", false
	}
	data, err := blob.Load()
	if err != nil || len(data) == 0 {
		return "", false
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", false
	}
	if err := durablefile.Write(path, data, 0o640); err != nil {
		log.Printf("agent_update_artifact_fill_failed tenant=%s target=%s/%s version=%s err=%v", tenantID,
			platform, arch, version, err)
		return "", false
	}
	log.Printf("agent_update_artifact_filled tenant=%s target=%s/%s version=%s bytes=%d — this node did not "+
		"hold the bytes and took them from the deployment's shelf", tenantID, platform, arch, version, len(data))
	return path, true
}

// WithArtifactDir names where this store's bytes are kept. Set once, at wiring; it is not part of the store's
// own persistence.
func (s *publishedAgentUpdateStore) WithArtifactDir(dir string) *publishedAgentUpdateStore {
	if s == nil {
		return s
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifactDir = strings.TrimSpace(dir)
	return s
}

// publishedStoreFile is the on-disk shape. A bare map is the pre-pending format and still loads.
//
// ★ Legacy IS PERSISTED (2026-08-12, sixth review). It was held only in memory: LoadFrom moved the pre-tenant
// entries out of `active` and persistLocked wrote `active` and `pending` — so the FIRST publish by any tenant
// rewrote the file without them, and the next restart answered "nothing published" to every tenant that had
// been relying on the fallback. A read-only fallback that a single unrelated write destroys is not a fallback;
// it is a delay before the same outage.
type publishedStoreFile struct {
	Schema  string                          `json:"schema"`
	Active  map[string]agentpolicy.Envelope `json:"active"`
	Pending map[string]agentpolicy.Envelope `json:"pending,omitempty"`
	Legacy  map[string]agentpolicy.Envelope `json:"legacy,omitempty"`
}

// tenantTargetKey is how the published set is indexed: the tenant FIRST, so a lookup cannot accidentally cross
// one. platform/arch alone was the bug.
// agentUpdateCatalogueScope is the deployment's own shelf of releases: what EXISTS, signed, with its bytes.
//
// ★★★ WHAT EXISTS AND WHAT AN ORGANIZATION RUNS ARE TWO THINGS, AND THIS STORE HELD ONE (2026-08-28, measured
// by publishing a real notarised package and then asking a device of another organization for it: 404).
//
// The published set was keyed per organization, so "the version this deployment distributes" could only be
// expressed by writing it into each organization separately — and the screen that writes it was hidden inside
// every organization but the operator's. The result was a deployment where no customer could ever be offered a
// release at all.
//
// So the operator publishes ONCE, here. Which of these an organization runs is the organization's own
// question, answered elsewhere and by its own administrator: a tenant holds neither the vendor's signing
// identity nor this deployment's update-signing key, so it cannot mint a version — but choosing among the
// versions offered to it, and when to move, is exactly what managing its own fleet means.
//
// A reserved id rather than a flag: organization ids are minted as `tenant_` + base32, so this cannot collide
// with one, and it reads as itself in the persisted keys and on disk.
const agentUpdateCatalogueScope = "deployment"

// agentUpdatePublishScope is which shelf a publish writes to: the deployment's catalogue when the caller
// answers for the whole deployment, and one organization's own when an operator has entered it — which is how
// a single customer is given a build before the rest (a canary), and stays possible.
func agentUpdatePublishScope(r *http.Request) string {
	if adminAnsweringForTheDeployment(r) {
		return agentUpdateCatalogueScope
	}
	return adminTenantIDFromRequest(r)
}

// A present empty pin also names a scope (legacy single-tenant deployments).
// Resolve from verified identity/operator context, never from the pin itself.
func agentUpdateReadContextMatches(w http.ResponseWriter, r *http.Request, scope string) bool {
	q := r.URL.Query()
	if values, present := q["expected_tenant_id"]; present && (len(values) != 1 || values[0] != scope) {
		writeError(w, http.StatusConflict, fmt.Errorf("the release scope changed; reload before continuing"))
		return false
	}
	return true
}

func tenantTargetKey(tenantID, platform, arch string) string {
	return strings.ToLower(strings.TrimSpace(tenantID)) + "|" + updateTargetKey(platform, arch)
}

func newPublishedAgentUpdateStore() *publishedAgentUpdateStore {
	return &publishedAgentUpdateStore{envelopes: map[string]agentpolicy.Envelope{},
		pending: map[string]agentpolicy.Envelope{}, legacy: map[string]agentpolicy.Envelope{}}
}

// LoadFrom rehydrates the store. A missing file is a control plane that has published nothing; an unreadable
// one is an error, because answering "nothing is published" to a fleet because a file is corrupt would stall
// every device with no explanation anywhere.
// defaultTenant adopts keys written before the store was tenant-scoped.
//
// ★ A SECURITY FIX MUST NOT SILENTLY UNPUBLISH A FLEET (2026-08-12). The set used to be keyed
// "platform/arch"; it is now "tenant|platform/arch". Without this, the first restart after the change answers
// "nothing published" to every device that was being served a release — the fix would have looked exactly like
// the outage it was preventing. Legacy keys are adopted into the tenant this control plane serves and written
// back, so the migration happens once and is visible in the log.
// LoadFromPersister rehydrates from the SHARED store, which is where a deployment with more than one control
// plane must keep this. Same decoding, same refusals; only where the bytes come from differs.
func (s *publishedAgentUpdateStore) LoadFromPersister(blob blobstore.Persister, defaultTenant string) error {
	if s == nil || blob == nil {
		return nil
	}
	raw, err := blob.Load()
	if err != nil {
		return fmt.Errorf("read the published-update store: %w", err)
	}
	s.mu.Lock()
	s.blob = blob
	s.mu.Unlock()
	if len(raw) == 0 {
		return nil
	}
	return s.adopt(raw, "the shared store", defaultTenant)
}

func (s *publishedAgentUpdateStore) LoadFrom(path string, defaultTenant string) error {
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
		return fmt.Errorf("read the published-update store %s: %w", path, err)
	}
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	return s.adopt(raw, path, defaultTenant)
}

// adopt is the decoding both entry points share, so the shared store and the file cannot come to disagree
// about what a stored set means.
func (s *publishedAgentUpdateStore) adopt(raw []byte, where string, defaultTenant string) error {
	var file publishedStoreFile
	envelopes := map[string]agentpolicy.Envelope{}
	pending := map[string]agentpolicy.Envelope{}
	legacyStored := map[string]agentpolicy.Envelope{}
	if jerr := json.Unmarshal(raw, &file); jerr == nil && (file.Active != nil || file.Pending != nil ||
		file.Legacy != nil) {
		envelopes, pending, legacyStored = file.Active, file.Pending, file.Legacy
	} else if jerr2 := json.Unmarshal(raw, &envelopes); jerr2 != nil {
		return fmt.Errorf("the published-update store %s is unreadable (%w) — refusing to start and answer "+
			"\"nothing published\" to a fleet", where, jerr2)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if envelopes != nil {
		s.envelopes = envelopes
	}
	if pending == nil {
		pending = map[string]agentpolicy.Envelope{}
	}
	s.pending = pending
	// ★ PRE-TENANT ENTRIES BECOME A READ-ONLY GLOBAL FALLBACK, NOT ONE TENANT'S PROPERTY (2026-08-12, sixth
	// review — a correction to the migration written this morning).
	//
	// Those entries were previously answered to EVERY tenant, because the store had no idea tenants existed.
	// Adopting them into this control plane's own tenant is right for a single-tenant deployment and silently
	// wrong for a multi-tenant one: every other tenant's next pull would answer "nothing published" and its
	// fleet would drop out of updates, from an upgrade nobody could connect to the effect.
	//
	// So they are kept, unmodified, in `legacy`: served to any tenant that has nothing of its own, never
	// written to, and shadowed the moment that tenant publishes. The security property the scoping exists for
	// is about WRITES — one tenant's admin changing another's release — and it is unaffected: nothing writes
	// here, and every entry is still verified against the edge's pinned key before it reaches a device.
	legacy := map[string]agentpolicy.Envelope{}
	for k, v := range legacyStored {
		legacy[k] = v
	}
	for k, v := range s.envelopes {
		if !strings.Contains(k, "|") {
			legacy[k] = v
			delete(s.envelopes, k)
		}
	}
	for k := range s.pending {
		if !strings.Contains(k, "|") {
			// A pending entry from before tenants existed cannot be attributed and nothing can activate it.
			// Dropping it is safe: pending has never been served to anything.
			delete(s.pending, k)
		}
	}
	s.legacy = legacy
	if len(legacy) > 0 {
		log.Printf("published agent-update store: %d pre-tenant entry(ies) are served as a READ-ONLY GLOBAL "+
			"fallback to any tenant that has published nothing of its own (this control plane's own tenant is "+
			"%q). Publish per tenant to replace them; they cannot be modified in place", len(legacy), defaultTenant)
	}
	return nil
}

// Publish verifies the envelope against the pinned keys and stores it. Persisted BEFORE it is published, for
// the reason the rollout store learned the hard way: a 200 that outlives its own storage is a lie.
//
// bytesReady reports whether the artifact this manifest names is ALREADY here. When it is not — the normal
// case for a DSSE-delivered release, whose bytes are uploaded next — the manifest is held PENDING and the
// active set is left alone, so nothing is offered that cannot be served. MDM releases carry no bytes for us
// and go active immediately. Returns whether it went active.
func (s *publishedAgentUpdateStore) Publish(tenantID string, env agentpolicy.Envelope, trustedKeys []string,
	now time.Time, bytesReady func(agentupdate.Manifest) bool) (agentupdate.Manifest, bool, string, error) {
	// ★ THE VERIFIED KEY IS RETURNED, NOT STASHED (2026-08-12, seventh review). It used to be written into a
	// per-target map and read back after the mutation, so two concurrent publishes to one target could have
	// manifest A audited under manifest B's key — including when B then failed to persist. A request-local
	// value cannot be crossed with another request's.
	m, verifiedKey, err := agentupdate.OpenWithKey(env, trustedKeys, now)
	if err != nil {
		return agentupdate.Manifest{}, false, "", err
	}
	key := tenantTargetKey(tenantID, m.Platform, m.Arch)
	active := m.Delivery != agentupdate.DeliveryDSSE || (bytesReady != nil && bytesReady(m))

	s.mu.Lock()
	defer s.mu.Unlock()
	envelopes := copyEnvelopes(s.envelopes)
	pending := copyEnvelopes(s.pending)
	if active {
		envelopes[key] = env
		delete(pending, key)
	} else {
		pending[key] = env
	}
	if perr := s.persistLocked(envelopes, pending); perr != nil {
		return agentupdate.Manifest{}, false, "", perr
	}
	s.envelopes, s.pending = envelopes, pending
	return m, active, verifiedKey, nil
}

// Activate promotes a pending manifest once its bytes have landed and been verified. Persisted before it takes
// effect, and a no-op when there is nothing pending for that target.
//
// expectPayloadSHA256 is the manifest the CALLER verified those bytes against, and it is checked here under
// the lock.
//
// ★ OTHERWISE THE UPLOAD ACTIVATES WHATEVER IS PENDING WHEN IT FINISHES (2026-08-12, sixth review). An
// artifact upload reads the pending manifest, spends however long it takes streaming and hashing tens of
// megabytes, and then promotes "the pending entry" — which by then may be a DIFFERENT manifest a second admin
// PUT while the first was uploading. The bytes for A would activate B, whose artifact is not here at all, and
// every device would be offered a release that 404s. Comparing the signed payload digest makes the promotion
// refer to the same document the verification did.
func (s *publishedAgentUpdateStore) Activate(tenantID, platform, arch, expectPayloadSHA256 string) (bool, error) {
	if s == nil {
		return false, nil
	}
	key := tenantTargetKey(tenantID, platform, arch)
	s.mu.Lock()
	defer s.mu.Unlock()
	env, ok := s.pending[key]
	if !ok {
		return false, nil
	}
	if want := strings.TrimSpace(expectPayloadSHA256); want != "" && !strings.EqualFold(env.PayloadSHA256, want) {
		return false, fmt.Errorf("the release waiting for bytes changed while these were being uploaded (pending "+
			"manifest %s, these bytes were verified against %s): refusing to activate a release whose artifact "+
			"is not the one just stored", env.PayloadSHA256, want)
	}
	envelopes := copyEnvelopes(s.envelopes)
	pending := copyEnvelopes(s.pending)
	envelopes[key] = env
	delete(pending, key)
	if perr := s.persistLocked(envelopes, pending); perr != nil {
		return false, perr
	}
	s.envelopes, s.pending = envelopes, pending
	return true, nil
}

// PendingFor is the manifest a target is WAITING to activate, if any. The artifact upload checks its bytes
// against this one: the pending manifest is what names the digest those bytes must have.
func (s *publishedAgentUpdateStore) PendingFor(tenantID string) map[string]agentpolicy.Envelope {
	if s == nil {
		return nil
	}
	return scopedTo(s.pendingSnapshot(), tenantID)
}

func (s *publishedAgentUpdateStore) pendingSnapshot() map[string]agentpolicy.Envelope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyEnvelopes(s.pending)
}

func copyEnvelopes(in map[string]agentpolicy.Envelope) map[string]agentpolicy.Envelope {
	out := make(map[string]agentpolicy.Envelope, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func scopedTo(all map[string]agentpolicy.Envelope, tenantID string) map[string]agentpolicy.Envelope {
	prefix := strings.ToLower(strings.TrimSpace(tenantID)) + "|"
	out := map[string]agentpolicy.Envelope{}
	for k, v := range all {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return out
}

// ForTenant returns only that tenant's published set, keyed platform/arch — which is all any caller, edge or
// admin, is entitled to see or act on.
// Tenants lists every tenant this store holds an ACTIVE release for.
//
// ★ IT EXISTS BECAUSE THE BOOT RESEED KNEW ONLY ONE (2026-08-13, thirtieth review #10). The twenty-ninth
// review's fix rebuilt the device-facing set from the durable store at startup — for the Edge's own bundle
// tenant. On a multi-tenant control plane every OTHER tenant's API-published release stayed un-offered after a
// restart, with the admin screen showing "active" and devices getting 404: the same symptom that fix was
// written to end, for everyone except the one tenant it was tested with.
func (s *publishedAgentUpdateStore) Tenants() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for key := range s.envelopes {
		tenant, _, ok := strings.Cut(key, "|")
		if !ok || strings.TrimSpace(tenant) == "" || seen[tenant] {
			continue
		}
		seen[tenant] = true
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

func (s *publishedAgentUpdateStore) ForTenant(tenantID string) map[string]agentpolicy.Envelope {
	if s == nil {
		return nil
	}
	prefix := strings.ToLower(strings.TrimSpace(tenantID)) + "|"
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]agentpolicy.Envelope{}
	// The pre-tenant fallback first, so anything above SHADOWS it rather than competing with it.
	for k, v := range s.legacy {
		out[k] = v
	}
	// ★ THEN THE DEPLOYMENT'S CATALOGUE — what the operator published once, offered to every organization.
	// Before this, an organization saw only what somebody had written into IT, which on a deployment with more
	// than one customer meant nothing at all.
	cataloguePrefix := agentUpdateCatalogueScope + "|"
	if !strings.EqualFold(strings.TrimSpace(tenantID), agentUpdateCatalogueScope) {
		for k, v := range s.envelopes {
			if strings.HasPrefix(k, cataloguePrefix) {
				out[strings.TrimPrefix(k, cataloguePrefix)] = v
			}
		}
	}
	// And last this organization's own, which is how one customer is given a build the others are not.
	for k, v := range s.envelopes {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return out
}

// CountForTenant is how many releases were published TO ONE ORGANIZATION — its own shelf, active and pending.
//
// ★ THE CATALOGUE IS NOT COUNTED, AND MUST NOT BE. What every organization is offered belongs to the
// deployment; a customer leaving does not unpublish the build the rest are taking. Only the canary shelf, the
// one an operator wrote while standing inside that organization, is a record of them.
func (s *publishedAgentUpdateStore) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	prefix := tenantShelfPrefix(tenantID)
	if prefix == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for k := range s.envelopes {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	for k := range s.pending {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// RemoveTenant erases an organization's own shelf, documents and bytes, and persists before returning.
func (s *publishedAgentUpdateStore) RemoveTenant(tenantID string) int {
	n, _ := s.RemoveTenantChecked(tenantID)
	return n
}

func (s *publishedAgentUpdateStore) RemoveTenantChecked(tenantID string) (int, error) {
	if s == nil {
		return 0, nil
	}
	prefix := tenantShelfPrefix(tenantID)
	if prefix == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	envelopes := map[string]agentpolicy.Envelope{}
	pending := map[string]agentpolicy.Envelope{}
	removed := 0
	for k, v := range s.envelopes {
		if strings.HasPrefix(k, prefix) {
			removed++
			continue
		}
		envelopes[k] = v
	}
	for k, v := range s.pending {
		if strings.HasPrefix(k, prefix) {
			removed++
			continue
		}
		pending[k] = v
	}
	// An empty manifest shelf can still have artifact cleanup left to retry.
	if removed > 0 {
		if err := s.persistLocked(envelopes, pending); err != nil {
			return 0, err
		}
		s.envelopes, s.pending = envelopes, pending
	}

	// ★ AND THE BYTES. A signed installer built for one customer is as much theirs as the manifest naming it,
	// and it is the larger residue of the two. Its absence is not an error: an organization can have had a
	// manifest published and never the artifact.
	if shelf := tenantArtifactDir(s.artifactDir, tenantID); shelf != "" {
		if rerr := os.RemoveAll(shelf); rerr != nil {
			log.Printf("agent_update_artifacts_not_erased tenant=%s err=%v — the manifests are gone and the "+
				"bytes are still on this node's disk", tenantID, rerr)
			return 0, rerr
		}
	}
	// And on the deployment's shelf, where every other control plane would still be able to hand them over.
	if s.shelf != nil && s.shelf.forget != nil {
		if ferr := s.shelf.forget(tenantID); ferr != nil {
			log.Printf("agent_update_artifacts_not_erased_shared tenant=%s err=%v — the manifests are gone and "+
				"the bytes are still on the deployment's shelf", tenantID, ferr)
			return 0, ferr
		}
	}
	return removed, nil
}

// tenantArtifactDir is where one organization's own release bytes live, or "" when there is no such directory
// to name — no artifact directory on this node, no tenant, or a tenant id that has no business being a path
// component. Same refusals as artifactStorePath, which is the only other thing that builds this path.
func tenantArtifactDir(dir, tenantID string) string {
	d := strings.TrimSpace(dir)
	t := strings.ToLower(strings.TrimSpace(tenantID))
	if d == "" || t == "" || strings.ContainsAny(t, `/\`) || strings.Contains(t, "..") {
		return ""
	}
	return filepath.Join(d, t)
}

// tenantShelfPrefix is the key prefix of one organization's own shelf, or "" for anything that is not one —
// including the deployment's catalogue, which no tenant erasure may touch.
func tenantShelfPrefix(tenantID string) string {
	t := strings.ToLower(strings.TrimSpace(tenantID))
	if t == "" || t == agentUpdateCatalogueScope {
		return ""
	}
	return t + "|"
}

func (s *publishedAgentUpdateStore) persistLocked(envelopes, pending map[string]agentpolicy.Envelope) error {
	if s.blob == nil && strings.TrimSpace(s.path) == "" {
		return nil
	}
	b, err := json.MarshalIndent(publishedStoreFile{Schema: "published_agent_updates.v2", Active: envelopes,
		Pending: pending, Legacy: s.legacy}, "", "  ")
	if err != nil {
		return err
	}
	// ★ THE SHARED STORE WINS. A deployment with more than one control plane must not keep this on the node
	// that happened to serve the publish — see the note on the field.
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

// publishedStoreOrEmpty keeps the handlers from having to nil-check: a process with no durable store still
// answers, it simply has nothing to answer with.
func publishedStoreOrEmpty(s *publishedAgentUpdateStore) *publishedAgentUpdateStore {
	if s == nil {
		return newPublishedAgentUpdateStore()
	}
	return s
}

// artifactStorePath is where the control plane keeps the bytes of a published release, PER TENANT.
//
// ★ THE ENVELOPES WERE SCOPED AND THE BYTES WERE NOT (2026-08-12, sixth review). The path was
// platform-arch-version, so two tenants publishing the same version number — which is the NORMAL case, since
// everyone runs "0.2.7" — wrote to one file and overwrote each other's signed artifact. The manifest scoping
// stopped one tenant changing another's DOCUMENT while leaving the BYTES that document names shared, which is
// the same defect one layer down.
//
// Empty tenant returns "", so a caller that has not resolved a tenant cannot accidentally address the flat
// path and reintroduce the sharing.
func artifactStorePath(dir, tenantID, platform, arch, version string) string {
	name := artifactFileName(platform, arch, version)
	if name == "" {
		return ""
	}
	t := strings.ToLower(strings.TrimSpace(tenantID))
	if t == "" || strings.ContainsAny(t, `/\`) || strings.Contains(t, "..") {
		return ""
	}
	return filepath.Join(dir, t, name)
}

// artifactReadPath is where a target's bytes are FOUND, which is not always where new ones are written.
//
// ★ ONE RULE FOR MANIFESTS AND BYTES (2026-08-12, sixth review, correcting this morning's fix). The store
// serves pre-tenant manifests as a read-only GLOBAL fallback — every tenant sees them, exactly as before the
// keys carried a tenant. Startup then MOVED each flat artifact into the control plane's own tenant, so every
// other tenant received an active legacy manifest whose bytes were not at its tenant path: an active release
// that 404s, which is the failure the pending/active split exists to prevent, reintroduced by the migration
// meant to support it.
//
// So nothing is moved. New uploads are written per tenant; a lookup that finds nothing there falls back to the
// flat path, read-only, which is the same shape the manifest fallback has. When a tenant publishes its own
// release the tenant path exists and the fallback is never consulted for it.
func artifactReadPath(dir, tenantID, platform, arch, version string) string {
	if p := artifactStorePath(dir, tenantID, platform, arch, version); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// ★ THEN THE DEPLOYMENT'S CATALOGUE, for the same reason the manifest lookup consults it: the release an
	// organization is offered was published once, by the operator, and its bytes live on that shelf. Without
	// this the manifest resolves and the download 404s, which is the exact shape the pending/active split
	// exists to prevent.
	if !strings.EqualFold(strings.TrimSpace(tenantID), agentUpdateCatalogueScope) {
		if p := artifactStorePath(dir, agentUpdateCatalogueScope, platform, arch, version); p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	name := artifactFileName(platform, arch, version)
	if name == "" || strings.TrimSpace(dir) == "" {
		return ""
	}
	flat := filepath.Join(dir, name)
	if _, err := os.Stat(flat); err == nil {
		return flat
	}
	// Neither exists: answer the tenant path, so the error a caller reports names where the bytes SHOULD be.
	return artifactStorePath(dir, tenantID, platform, arch, version)
}

// artifactBytesMatch reports whether the file at path IS the artifact the manifest names — size and digest,
// not size alone.
//
// ★ SIZE WAS NOT AN IDENTITY (2026-08-12, sixth review). "Publish activates only when the bytes are here" was
// decided by a stat: a leftover file of the same length from a previous build, or from before the path carried
// a tenant, made a release go active over bytes nothing had checked. The digest is in the signed manifest and
// hashing an installer takes tens of milliseconds on a path that runs when somebody publishes — there was
// never a reason to guess.
func artifactBytesMatch(path string, m agentupdate.Manifest) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, serr := f.Stat()
	if serr != nil || fi.Size() != m.ArtifactSize {
		return false
	}
	sum := sha256.New()
	if _, cerr := io.Copy(sum, f); cerr != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(sum.Sum(nil)), m.ArtifactSHA256)
}

// registerAgentUpdateArtifactAdminRoutes lets the control plane hold the BYTES, not only the document naming
// them.
//
// ★ WHY THE DOCUMENT ALONE WAS NOT ENOUGH (2026-08-12). With manifests centralised and artifacts still a
// directory per Edge, a release could be current fleet-wide while the node serving a given device did not have
// it — every endpoint on that Edge failing to stage, with the release looking perfectly published from the
// control plane. Half an authority is a new way to be inconsistent, not a smaller version of the old one.
//
// The bytes are checked against the DIGEST IN THE PUBLISHED MANIFEST before they are stored, so the control
// plane cannot become a place where an artifact and its manifest disagree — the mistake would otherwise be
// discovered by every device in the fleet, one at a time.
func registerAgentUpdateArtifactAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	store *publishedAgentUpdateStore, trustedKeys []string, dir string, isEnforcingEdge bool, writer *logs.Writer,
	evaluator decision.Evaluator, deviceFacing *publishedUpdates) {
	mux.HandleFunc("PUT /admin/agent-update-artifact", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		tenantID := agentUpdatePublishScope(r)
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		if isEnforcingEdge {
			writeError(w, http.StatusConflict, fmt.Errorf("this edge pulls release artifacts from the control "+
				"plane; upload there instead"))
			return
		}
		if strings.TrimSpace(dir) == "" {
			writeError(w, http.StatusPreconditionFailed, fmt.Errorf("this process has no artifact directory "+
				"(-agent-update-manifest-dir), so it has nowhere to put the bytes"))
			return
		}
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		arch := strings.TrimSpace(r.URL.Query().Get("arch"))
		// The bytes land on the same verified publication shelf.
		// ★ PENDING FIRST. A release published a moment ago is waiting for exactly these bytes; the active
		// entry is the PREVIOUS release, whose artifact is already here. Checking the bytes against the active
		// manifest would reject the upload that is supposed to activate the new one.
		env, ok := store.PendingFor(tenantID)[updateTargetKey(platform, arch)]
		if !ok {
			env, ok = store.ForTenant(tenantID)[updateTargetKey(platform, arch)]
		}
		if !ok {
			// ★ MANIFEST FIRST, DELIBERATELY. The manifest is what says which bytes are authorised; accepting
			// bytes with nothing to check them against would make this endpoint a place to stage anything.
			writeError(w, http.StatusPreconditionFailed, fmt.Errorf("nothing is published for %s/%s yet: publish "+
				"the signed manifest first, then the artifact it names", platform, arch))
			return
		}
		if pins, present := r.URL.Query()["expected_manifest_sha256"]; present &&
			(len(pins) != 1 || !strings.EqualFold(pins[0], env.PayloadSHA256)) {
			writeError(w, http.StatusConflict, fmt.Errorf("the release waiting for this package changed; reload before uploading"))
			return
		}

		// OpenWithKey, so the audit below names the key that ACTUALLY verified this envelope rather than the
		// unsigned label attached to it. Resolved here rather than remembered from the publish, because a
		// control plane that restarted between the two would otherwise record "unknown" for an ordinary upload.
		m, verifiedKey, oerr := agentupdate.OpenWithKey(env, trustedKeys, time.Now())
		if oerr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the published manifest for %s/%s no longer "+
				"verifies here: %w", platform, arch, oerr))
			return
		}
		path := artifactStorePath(dir, tenantID, m.Platform, m.Arch, m.Version)
		if path == "" {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the published manifest names an artifact this "+
				"process will not store"))
			return
		}
		// ★ THE TENANT'S DIRECTORY, NOT THE ROOT (2026-08-12, sixth review). path now lives under
		// dir/<tenant>/, and creating only dir meant the rename below failed with ENOENT for every tenant that
		// had no migrated artifacts — which is EVERY new tenant, on its first upload. The scoping fix would
		// have made onboarding impossible.
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		tmp, terr := os.CreateTemp(filepath.Dir(path), ".artifact-*")
		if terr != nil {
			writeError(w, http.StatusInternalServerError, terr)
			return
		}
		tmpName := tmp.Name()
		defer func() { tmp.Close(); os.Remove(tmpName) }()
		sum := sha256.New()
		// Bounded by what the manifest declares, plus one byte so an oversized body is DETECTED rather than
		// silently truncated into something that then fails the digest for a misleading reason.
		written, cerr := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(r.Body, m.ArtifactSize+1))
		if cerr != nil {
			writeError(w, http.StatusInternalServerError, cerr)
			return
		}
		got := hex.EncodeToString(sum.Sum(nil))
		if written != m.ArtifactSize || !strings.EqualFold(got, m.ArtifactSHA256) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("these bytes are not the ones %s authorises: got %d "+
				"bytes sha256:%s, the manifest declares %d bytes sha256:%s", m.Version, written, got,
				m.ArtifactSize, m.ArtifactSHA256))
			return
		}
		if err := tmp.Sync(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		tmp.Close()
		_ = os.Chmod(tmpName, 0o640)
		// ★ THE PENDING MANIFEST IS RE-CHECKED BEFORE THE BYTES LAND (2026-08-12, ninth review). The path is
		// keyed by VERSION, and two uploads for the same version with different digests — a re-sign, a rebuild —
		// could interleave: B activates, then A finishes and renames ITS bytes over the file B's manifest names.
		// A's activation is refused (the payload digests differ), so the refusal read like the system had held,
		// while every device staging B now failed the digest check and the fleet could not update at all.
		//
		// Checking here does not make the rename atomic with the check, and it does not have to: it closes the
		// window that matters — an upload finishing against a manifest that is no longer the pending one — and
		// the alternative, storing by digest, changes the device-facing path for a case that needs an operator
		// racing themselves.
		if current, still := store.PendingFor(tenantID)[updateTargetKey(platform, arch)]; still &&
			!strings.EqualFold(current.PayloadSHA256, env.PayloadSHA256) {
			writeError(w, http.StatusConflict, fmt.Errorf("the release waiting for bytes changed while these were "+
				"being uploaded (pending manifest %s, these bytes were verified against %s): they were NOT stored, "+
				"because writing them would replace the artifact the current manifest names",
				current.PayloadSHA256, env.PayloadSHA256))
			return
		}
		if err := os.Rename(tmpName, path); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		log.Printf("agent_update_artifact_stored target=%s/%s version=%s bytes=%d", m.Platform, m.Arch, m.Version, written)
		// ★★★ AND ONTO THE DEPLOYMENT'S SHELF, BEFORE THE RELEASE IS ACTIVATED (2026-08-28). Activation means
		// "the fleet can fetch this". On a deployment with more than one control plane, bytes that reached only
		// the node serving this upload make that a promise the other node cannot keep — a device is answered
		// 404 by whichever one the front door picked. So a shelving failure fails the REQUEST: the manifest
		// stays pending, the operator is told exactly what happened, and retrying the upload is the whole fix.
		if serr := store.shelveArtifact(path, tenantID, m.Platform, m.Arch, m.Version); serr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("these bytes are on this control plane and "+
				"could NOT be put on the deployment's shared shelf (%w), so another control plane would answer "+
				"404 for them: the release is NOT activated. Upload it again", serr))
			return
		}
		// ★ THE ACTIVATION IS RECORDED BEFORE IT HAPPENS (2026-08-12, sixth review). Activation is the moment a
		// build becomes reachable by a fleet — the publish attempt was recorded, and THIS is the state change
		// that matters — and the audit was appended afterwards with its failure logged and ignored. So the one
		// case that counts, "the audit is gone", answered 200 over a release nobody can account for. Same shape
		// as the publish path, which learned it an hour earlier.
		attempt := agentUpdatePublishAuditLog(tenantID, m, env, evaluator, sourceIPFromRequest(r), actorOf(r),
			verifiedKey)
		attempt.EventType = "agent_update_activate_attempted"
		attemptResult := "attempted"
		attempt.Result = &attemptResult
		if aaerr := writer.Append("audit.log.jsonl", attempt); aaerr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the bytes are stored but this release was "+
				"NOT activated because the attempt could not be recorded (%w): a build reachable by a fleet with "+
				"no accountable trail is not something this control plane will do", aaerr))
			return
		}
		// ★ THE BYTES ARE WHAT ACTIVATE THE RELEASE. Until this line the manifest was published but held
		// pending, and the fleet was still being offered whatever could actually be served. Persisted before it
		// takes effect, like every other write here.
		activated, aerr := store.Activate(tenantID, m.Platform, m.Arch, env.PayloadSHA256)
		if aerr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the bytes are stored but the release could "+
				"NOT be activated (%w): it stays pending rather than being offered from a state a restart would "+
				"forget", aerr))
			return
		}
		if activated {
			log.Printf("agent_update_activated tenant=%s target=%s/%s version=%s — its artifact is here, so this "+
				"is now what the fleet is offered", tenantID, m.Platform, m.Arch, m.Version)
			// ★ AND THE SET DEVICES READ IS A DIFFERENT ONE (2026-08-13, twenty-eighth review). Publishing wrote
			// to the admin store; GET /steer/agent-update-manifest serves `publishedUpdates`, which was filled
			// once at boot from the manifest directory and afterwards only by the CP→Edge pull — a loop gated on
			// -agent-update-source-url, which a control plane does not set. So on the reference topology every
			// screen and every audit record said "active" and no device was ever offered anything. Activation
			// now reaches the set that answers devices, in the same process, at the moment it becomes true.
			refreshDeviceFacingPublished(deviceFacing, store, tenantID, trustedKeys)
			rec := agentUpdatePublishAuditLog(tenantID, m, env, evaluator, sourceIPFromRequest(r), actorOf(r),
				verifiedKey)
			rec.EventType = "agent_update_activated"
			activatedAction := "agent_update_activate"
			rec.Action = &activatedAction
			// ★ AND THE OUTCOME IS NOT OPTIONAL EITHER (2026-08-12, seventh review). Recording the ATTEMPT
			// before activation was half the fix: if THIS append fails, the fleet has a release it can reach
			// and the trail says only that somebody tried. The release is not withdrawn — it is already
			// serving, and withdrawing it to satisfy the audit would be an outage caused by bookkeeping — so
			// the request FAILS LOUDLY instead, naming what an operator has to reconcile by hand.
			if auerr := writer.Append("audit.log.jsonl", rec); auerr != nil {
				log.Printf("agent_update_activate_audit_lost tenant=%s version=%s err=%v", tenantID, m.Version, auerr)
				writeError(w, http.StatusInternalServerError, fmt.Errorf("%s IS NOW ACTIVE for %s/%s and its "+
					"activation could NOT be recorded (%w): the trail holds an unresolved attempt. Reconcile it "+
					"by hand — the release was not withdrawn, because withdrawing a serving release to satisfy "+
					"an audit would be an outage caused by bookkeeping", m.Version, m.Platform, m.Arch, auerr))
				return
			}
		}
		current, present := store.ForTenant(tenantID)[updateTargetKey(m.Platform, m.Arch)]
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_agent_updates.v1",
			"tenant_id": tenantID, "manifest_sha256": env.PayloadSHA256,
			"stored": map[string]any{"platform": m.Platform, "arch": m.Arch, "version": m.Version,
				"bytes": written, "artifact_sha256": got},
			"activated": activated,
			"active":    present && strings.EqualFold(current.PayloadSHA256, env.PayloadSHA256)})
	}))

	// The device-facing artifact route is unauthenticated by design (its integrity is the digest in the signed
	// manifest); THIS one is admin-only, because it is how an Edge asks the control plane for bytes it does not
	// have and there is no reason to widen that.
	mux.HandleFunc("GET /admin/agent-update-artifact", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		// Existing bundle and replication clients read the tenant-effective package.
		// The catalogue explicitly asks for its publication view; the request never
		// supplies a tenant to read outside verified identity/operator context.
		tenantID := adminTenantIDFromRequest(r)
		if views, present := r.URL.Query()["artifact_scope"]; present {
			if len(views) != 1 || (views[0] != "tenant" && views[0] != "publication") {
				writeError(w, http.StatusBadRequest, fmt.Errorf("artifact_scope must be tenant or publication"))
				return
			}
			if views[0] == "publication" {
				tenantID = agentUpdatePublishScope(r)
			}
		}
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		arch := strings.TrimSpace(r.URL.Query().Get("arch"))
		env, ok := store.ForTenant(tenantID)[updateTargetKey(platform, arch)]
		if !ok {
			http.Error(w, "nothing is published for that target", http.StatusNotFound)
			return
		}
		if pins, present := r.URL.Query()["expected_manifest_sha256"]; present &&
			(len(pins) != 1 || !strings.EqualFold(pins[0], env.PayloadSHA256)) {
			writeError(w, http.StatusConflict, fmt.Errorf("the published release changed; reload before downloading"))
			return
		}
		m, oerr := agentupdate.Open(env, trustedKeys, time.Now())
		if oerr != nil {
			http.Error(w, "the published manifest does not verify here", http.StatusInternalServerError)
			return
		}
		path := store.artifactPathFor(dir, tenantID, m.Platform, m.Arch, m.Version)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "the control plane does not hold this release's artifact", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set(agentupdate.ArtifactVersionHeader, m.Version)
		w.Header().Set("X-Dsse-Agent-Update-Scope", tenantID)
		w.Header().Set("X-Dsse-Agent-Update-Manifest-SHA256", env.PayloadSHA256)
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
	}))
}

// actorOf is who is acting, for the records that name them. Empty identity rather than a nil check at every
// call site: an unauthenticated request cannot reach these handlers.
func actorOf(r *http.Request) adminIdentity {
	identity, _ := adminIdentityFromRequest(r)
	return identity
}

// registerAgentUpdatePublishRoutes serves the control plane's published set.
func registerAgentUpdatePublishRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	store *publishedAgentUpdateStore, trustedKeys []string, isEnforcingEdge bool, writer *logs.Writer,
	evaluator decision.Evaluator, artifactDir string, deviceFacing *publishedUpdates,
	signer *agentpolicy.Signer, ratchet *agentUpdateSignRatchet) {
	mux.HandleFunc("GET /admin/agent-updates", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		// the operator standing outside an organization is looking at the catalogue — see agentUpdateCatalogueScope.
		tenantID := agentUpdatePublishScope(r)
		// envelopes is what an EDGE adopts, and it holds only releases whose bytes are here. pending is for the
		// operator: published, verified, and waiting on its artifact.
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_agent_updates.v1",
			"tenant_id":      tenantID,
			"envelopes":      store.ForTenant(tenantID),
			"pending":        store.PendingFor(tenantID),
		})
	}))
	// ★ ONE PUBLISH PATH, TWO DOORS INTO IT (2026-08-13). PUT takes an envelope signed somewhere else; POST
	// takes the FIELDS and has this control plane sign them. Everything after the signature — the pre-recorded
	// audit attempt, the verification against the pinned keys, the pending/active decision, the device-facing
	// refresh — must be identical, because a second copy of that sequence is a second place for the rules to
	// drift, and the rules are what stands between an admin request and code running as root on a fleet.
	publish := func(w http.ResponseWriter, r *http.Request, env agentpolicy.Envelope, tenantID string) {
		actor := actorOf(r)
		// ★ THE ATTEMPT IS RECORDED BEFORE THE STORE IS TOUCHED, AND THE REQUEST FAILS IF IT CANNOT BE
		// (2026-08-12, sixth review). The outcome record was appended AFTER the state change and its failure was
		// logged and ignored — so the one case that matters, "the audit is gone", answered 200 and left a
		// published release nobody can account for. The rollout store settled this shape hours earlier and this
		// path did not adopt it. A reader who finds an attempt with no outcome knows exactly what to check.
		attempt := agentUpdatePublishAuditLog(tenantID, agentupdate.Manifest{}, env, evaluator,
			sourceIPFromRequest(r), actor, "")
		attempt.EventType = "agent_update_publish_attempted"
		attempted := "attempted"
		attempt.Result = &attempted
		attempt.Metadata["manifest_sha256"] = env.PayloadSHA256
		if aerr := writer.Append("audit.log.jsonl", attempt); aerr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("this release was NOT published because the "+
				"attempt could not be recorded (%w): code put in front of a fleet with no accountable trail is "+
				"not something this control plane will do", aerr))
			return
		}
		// bytesReady: a DSSE release is only ACTIVE once its artifact is here. Republishing a manifest whose
		// bytes are already stored (a re-sign, a re-push of the same version) activates immediately.
		m, active, verifiedKey, err := store.Publish(tenantID, env, trustedKeys, time.Now(), func(man agentupdate.Manifest) bool {
			p := store.artifactPathFor(artifactDir, tenantID, man.Platform, man.Arch, man.Version)
			if p == "" {
				return false
			}
			return artifactBytesMatch(p, man)
		})
		if err != nil {
			// ★ The refusal is the point of verifying here: a wrongly signed or expired manifest fails on the
			// machine where the release was made, not on every endpoint that stages it and then refuses.
			writeError(w, http.StatusBadRequest, fmt.Errorf("this manifest will not be published: %w", err))
			return
		}
		log.Printf("agent_update_published_by_admin tenant=%s target=%s/%s version=%s delivery=%s digest=%s",
			tenantID, m.Platform, m.Arch, m.Version, m.Delivery, m.ArtifactSHA256)
		// ★ PUBLISHING CODE DESERVES ITS OWN RECORD (2026-08-12, fifth review). The uniform API-write audit
		// carries method, path and status — which cannot answer the question actually asked after an incident:
		// WHICH build, by WHAT digest, signed under WHICH key, did somebody put in front of a fleet. The current
		// value is overwritten by the next publication, so without this the answer is unrecoverable.
		outcome := agentUpdatePublishAuditLog(tenantID, m, env, evaluator, sourceIPFromRequest(r), actor,
			verifiedKey)
		outcome.Metadata["state"] = map[bool]string{true: "active", false: "pending"}[active]
		// ★ AND THE PUBLISH OUTCOME IS NOT OPTIONAL EITHER (2026-08-12, eighth review). The activation path was
		// made to fail loudly on this and the publish path was left logging it — so a release could be stored,
		// active or pending, with a trail holding nothing but an unresolved attempt, and the caller told 200.
		// The state is NOT rolled back: it is stored and, when active, already being served, and undoing it to
		// satisfy the audit would be an outage caused by bookkeeping. The caller is told what to reconcile.
		if aerr := writer.Append("audit.log.jsonl", outcome); aerr != nil {
			log.Printf("agent_update_publish_audit_lost tenant=%s version=%s err=%v (the ATTEMPT is recorded and "+
				"this outcome is not — treat the attempt as unresolved)", tenantID, m.Version, aerr)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("%s IS STORED for %s/%s (state=%s) and the "+
				"outcome could NOT be recorded (%w): the trail holds an unresolved attempt. Reconcile it by hand "+
				"— the release was not withdrawn, because undoing a stored release to satisfy an audit would be "+
				"an outage caused by bookkeeping", m.Version, m.Platform, m.Arch,
				map[bool]string{true: "active", false: "pending"}[active], aerr))
			return
		}
		// ★ AND THE OTHER TWO WAYS A RELEASE BECOMES ACTIVE (2026-08-13, twenty-ninth review). The refresh was
		// added to the artifact upload only, so an mdm target — which carries no bytes for us and activates
		// immediately — and a re-publish over an artifact already present both left the device-facing set
		// untouched. Same defect as before the fix, through the two doors the fix did not cover.
		if active {
			refreshDeviceFacingPublished(deviceFacing, store, tenantID, trustedKeys)
		}
		state, reach := "active", "edges pull the published set on their next poll, and devices ask their edge "+
			"on theirs"
		if !active {
			state = "pending"
			reach = "NOTHING has changed for the fleet yet: this release is held until its artifact is uploaded " +
				"(PUT /admin/agent-update-artifact). Until then edges keep being offered the release that can " +
				"actually be served"
		}
		if ratchet != nil {
			// Recorded for BOTH doors. A release published through PUT with an externally-signed envelope must
			// raise the floor too, or the ratchet could be walked backwards by alternating the two paths.
			if rerr := ratchet.Record(tenantID, m.Platform, m.Arch, m.Version); rerr != nil {
				log.Printf("agent_update_sign_floor_not_recorded tenant=%s target=%s/%s version=%s err=%v (the "+
					"release IS published; the downgrade floor did not move, so an older version could still be "+
					"signed for this target)", tenantID, m.Platform, m.Arch, m.Version, rerr)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_agent_updates.v1",
			"tenant_id":      tenantID, "manifest_sha256": env.PayloadSHA256,
			"published": map[string]any{"platform": m.Platform, "arch": m.Arch, "version": m.Version,
				"artifact_sha256": m.ArtifactSHA256, "artifact_size": m.ArtifactSize},
			"state":           state,
			"reaches_devices": reach,
		})
	}

	mux.HandleFunc("PUT /admin/agent-updates", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		tenantID := agentUpdatePublishScope(r)
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		// The same authority rule as the halt: an edge that PULLS is not the place to author, because a write
		// here would be overwritten by the next poll and reach nobody meanwhile.
		if isEnforcingEdge {
			writeError(w, http.StatusConflict, fmt.Errorf("this edge pulls its published releases from the control "+
				"plane; publish there instead"))
			return
		}
		if len(trustedKeys) == 0 {
			writeError(w, http.StatusPreconditionFailed, fmt.Errorf("this control plane pins no update-signing key, "+
				"so it cannot check what it would be handing to a fleet: set -agent-update-pin"))
			return
		}
		var env agentpolicy.Envelope
		if err := decodeLimitedJSONBody(w, r, &env, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode the signed manifest envelope: %w", err))
			return
		}
		publish(w, r, env, tenantID)
	}))

	// POST /admin/agent-updates — the operator states WHAT to release and this control plane signs it.
	//
	// ★ THE POINT IS THAT THE KEY NEVER LEAVES THE TOKEN, and the operator never handles it. Until now the only
	// way to publish was to sign on a laptop with dsse-signupdate and a file-based key — the most dangerous key
	// in the product, on somebody's disk, in a directory a backup tool syncs. The signer here is an HSM-backed
	// crypto.Signer, so the CP holds a handle and not a key.
	//
	// ★ AND IT IS SEPARATE FROM THE AGENT-POLICY KEY BY CONSTRUCTION, not by convention: main.go refuses to
	// start if the two key ids or public keys coincide, because one key signing both the release and the rollout
	// plan means a compromised release key can also lift the freeze that would stop it.
	mux.HandleFunc("POST /admin/agent-updates", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		tenantID := agentUpdatePublishScope(r)
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		if isEnforcingEdge {
			writeError(w, http.StatusConflict, fmt.Errorf("this edge pulls its published releases from the control "+
				"plane; publish there instead"))
			return
		}
		if signer == nil {
			writeError(w, http.StatusPreconditionFailed, fmt.Errorf("this control plane holds no update-signing "+
				"key, so it cannot mint a manifest: set -agent-update-hsm-agent-socket (and its token/key-id), or "+
				"sign elsewhere and PUT the envelope"))
			return
		}
		if len(trustedKeys) == 0 {
			writeError(w, http.StatusPreconditionFailed, fmt.Errorf("this control plane pins no update-signing key, "+
				"so it cannot check what it would be handing to a fleet: set -agent-update-pin"))
			return
		}
		// Strict decode, the same rule dsse-signupdate applies: a field this build does not understand is
		// refused here rather than signed into an artefact the fleet rejects for a reason invisible from the
		// release side.
		var m agentupdate.Manifest
		if err := decodeLimitedJSONBodyStrict(w, r, &m, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode the manifest fields: %w", err))
			return
		}
		// Signing uses the publication scope verified before the body was decoded.
		// ★ CHECKED BEFORE THE SIGNATURE, not after. A signed downgrade that is then refused has still been
		// signed, and an envelope that exists can be replayed at any edge that pins the key.
		if ratchet != nil {
			if err := ratchet.Check(tenantID, m.Platform, m.Arch, m.Version); err != nil {
				writeError(w, http.StatusConflict, err)
				return
			}
		}
		env, serr := agentupdate.Sign(signer, m, time.Now())
		if serr != nil {
			// Sign validates before it signs: a correctly-signed invalid manifest is the worst artefact this
			// endpoint could produce, because it looks like a key problem on thousands of endpoints at once.
			writeError(w, http.StatusBadRequest, fmt.Errorf("refusing to sign: %w", serr))
			return
		}
		// ★ THE ANNOUNCEMENT. One line per signature, naming what was authorised and under which key, because
		// this is the moment an operator authorised CODE to run as root across a fleet. The audit record written
		// inside publish carries the same facts durably; this is the one a human watching logs sees at the
		// moment it happens.
		log.Printf("★ agent_update_SIGNED_by_control_plane tenant=%s target=%s/%s version=%s delivery=%s "+
			"artifact_sha256=%s not_after=%s signing_key=%s actor=%s — every endpoint pinning that key will run "+
			"these bytes", tenantID, m.Platform, m.Arch, m.Version, m.Delivery, m.ArtifactSHA256, m.NotAfter,
			signer.PublicKeyHex(), actorOf(r).PrincipalID)
		publish(w, r, env, tenantID)
	}))

	// What this control plane will not sign below, per target. Readable because a refusal an operator cannot
	// anticipate is one they work around by inventing a version number.
	mux.HandleFunc("GET /admin/agent-update-sign-floor", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := agentUpdatePublishScope(r)
		if !agentUpdateReadContextMatches(w, r, tenantID) {
			return
		}
		holds := "no"
		if signer != nil {
			holds = signer.PublicKeyHex()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":     "admin_agent_update_sign_floor.v1",
			"tenant_id":          tenantID,
			"floors":             ratchet.FloorsForTenant(tenantID),
			"signing_public_key": holds,
			"rule": "this control plane signs a version equal to or newer than the floor for that target, never " +
				"older. Rolling a device BACK does not need a manifest and is unaffected.",
		})
	}))
}

// agentUpdateSource is an enforcing Edge pulling the published set.
type agentUpdateSource struct {
	url         string
	token       string
	trustedKeys []string
	artifactDir string
	interval    time.Duration
	client      *http.Client
	// tenantID is the enforcement tenant of THIS edge, checked against the tenant the control plane says it
	// answered for — the same rule the halt lane already applies, and for the same reason: an edge pointed at
	// the wrong control plane, or holding a token scoped to another tenant, must not hand ANOTHER TENANT'S
	// BUILD to its own devices. That is the one mistake in this file that ends with the wrong code running on
	// somebody's machines.
	tenantID string
}

func (s agentUpdateSource) fetch(ctx context.Context, now time.Time) (map[string]publishedUpdate, error) {
	url := strings.TrimRight(s.url, "/") + "/admin/agent-updates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	// ★ BOUNDED (2026-08-12, fifth review). The separation of the update-signing key from the control plane is
	// what limits a compromised CP to "cannot make the fleet run code" — it does not stop that CP from
	// answering a gigabyte of JSON, or ten thousand envelopes, to an Edge that decodes without a limit. The
	// cap is generous for a fleet's worth of platforms and nowhere near a memory problem.
	var body struct {
		TenantID  string                          `json:"tenant_id"`
		Envelopes map[string]agentpolicy.Envelope `json:"envelopes"`
	}
	if derr := json.NewDecoder(io.LimitReader(resp.Body, maxPublishedSetBytes)).Decode(&body); derr != nil {
		return nil, fmt.Errorf("decode the published set: %w", derr)
	}
	// ★★★ AND THE DEPLOYMENT'S CATALOGUE IS NOT "ANOTHER TENANT'S" (2026-08-28). This check exists so a
	// misdirected Edge cannot hand one customer's release to another's devices, and that is right. But an Edge
	// serves EVERY organization on this deployment, and the versions the operator publishes for all of them
	// arrive under the catalogue's name — so refusing it left every Edge carrying only its own enforcement
	// tenant's set, which on a deployment with customers is how no customer's device could be updated at all.
	answered := strings.TrimSpace(body.TenantID)
	if want := strings.TrimSpace(s.tenantID); want != "" && !strings.EqualFold(answered, want) &&
		!strings.EqualFold(answered, agentUpdateCatalogueScope) {
		return nil, fmt.Errorf("the control plane answered for tenant %q and this edge enforces %q — refusing to "+
			"offer another tenant's release to these devices", body.TenantID, want)
	}
	if len(body.Envelopes) > maxPublishedTargets {
		return nil, fmt.Errorf("the control plane answered with %d targets (limit %d): refusing to adopt a set "+
			"that size rather than filling this edge's memory with it", len(body.Envelopes), maxPublishedTargets)
	}
	out := make(map[string]publishedUpdate, len(body.Envelopes))
	for key, env := range body.Envelopes {
		// ★ VERIFIED HERE TOO, against THIS edge's pinned key. The control plane checked it before storing it,
		// and that is not a substitute: an edge that trusted the channel would be an edge whose fleet runs
		// whatever a compromised control plane hands it, which is precisely what pinning the key on the edge
		// exists to prevent.
		m, oerr := agentupdate.Open(env, s.trustedKeys, now)
		if oerr != nil {
			return nil, fmt.Errorf("the control plane published %s and this edge will not relay it: %w", key, oerr)
		}
		out[updateTargetKey(m.Platform, m.Arch)] = publishedUpdate{Manifest: m, Envelope: env,
			Source: "control plane"}
	}
	return out, nil
}

// serveable filters a published set down to what THIS edge can actually hand to a device.
//
// It is a method rather than an inline loop so the rule is exercised by a test instead of restated by one.
func (s agentUpdateSource) serveable(ctx context.Context, set, before map[string]publishedUpdate) map[string]publishedUpdate {
	out := make(map[string]publishedUpdate, len(set))
	for key, u := range set {
		if u.Manifest.Delivery != agentupdate.DeliveryDSSE {
			// MDM carries no bytes for us; the MDM already holds the payload and this edge never serves it.
			out[key] = u
			continue
		}
		// ★ NO ARTIFACT DIRECTORY IS NOT "EVERYTHING IS FINE" (2026-08-12, sixth review). An edge configured
		// without -agent-update-manifest-dir used to adopt every DSSE release unconditionally — and then answer
		// 404 to every device that asked for the bytes. A missing setting rendered identically to a working one,
		// which is the shape of defect this whole lane keeps producing. Keep what was being served, say why.
		if strings.TrimSpace(s.artifactDir) == "" {
			if prev, had := before[key]; had {
				out[key] = prev
			}
			log.Printf("agent-update sync: ★ %s publishes %s over DSSE delivery and this edge has NO artifact "+
				"directory (-agent-update-manifest-dir), so it could never hand over the bytes — not adopting it. "+
				"Devices would have received a manifest and a 404", key, u.Manifest.Version)
			continue
		}
		name := artifactFileName(u.Manifest.Platform, u.Manifest.Arch, u.Manifest.Version)
		if name == "" {
			continue
		}
		// ★ AND A FILE OF THE RIGHT NAME IS NOT THE ARTIFACT. Same version string, different bytes is the daily
		// case on a build box and the normal case after a re-sign; the old check was os.Stat. Adopting on the
		// name alone means the device-facing route serves a digest mismatch and every endpoint refuses to stage
		// — the fleet stops updating and the reason is on a machine nobody is looking at.
		local := filepath.Join(s.artifactDir, name)
		if artifactBytesMatch(local, u.Manifest) {
			out[key] = u
			continue
		}
		if _, serr := os.Stat(local); serr == nil {
			log.Printf("agent-update sync: ★ %s has a local file for %s that is NOT the artifact the manifest "+
				"names (size/digest mismatch) — refetching it rather than serving bytes nothing authorised",
				key, u.Manifest.Version)
			_ = os.Remove(local)
		}
		if ferr := s.fetchArtifact(ctx, u.Manifest); ferr != nil {
			if prev, had := before[key]; had {
				out[key] = prev
				log.Printf("agent-update sync: ★ %s publishes %s and its artifact is neither here nor "+
					"fetchable (%v) — this edge KEEPS OFFERING %s, which it can actually serve", key,
					u.Manifest.Version, ferr, prev.Manifest.Version)
			} else {
				log.Printf("agent-update sync: ★ %s publishes %s and its artifact is neither here nor "+
					"fetchable (%v) — this edge offers NOTHING for that target rather than a release it "+
					"cannot hand over", key, u.Manifest.Version, ferr)
			}
			continue
		}
		log.Printf("agent-update sync: fetched the %s artifact for %s from the control plane",
			u.Manifest.Version, key)
		out[key] = u
	}
	return out
}

func (s agentUpdateSource) run(ctx context.Context, published *publishedUpdates) {
	log.Printf("agent-update sync: pulling the published set from %s every %s", s.url, s.interval)
	first := true
	pull := func() {
		set, err := s.fetch(ctx, time.Now())
		if err != nil {
			log.Printf("agent-update sync: pull failed (keeping the current set): %v", err)
			return
		}
		before := published.targets()

		// ★ AN EDGE PUBLISHES ONLY WHAT IT CAN HAND OVER (2026-08-12, fifth review). The set used to be adopted
		// first and the artifacts fetched afterwards, so between those two lines — and for as long as a fetch
		// kept failing — every device was offered a release whose bytes answered 404. "Published" and "cannot be
		// staged" were true at the same time, which is the same shape as a halt that reaches nobody.
		//
		// So a dsse-delivered target whose artifact is not here, and cannot be fetched, keeps its PREVIOUS entry
		// rather than replacing it: the fleet stays on a release this Edge can actually serve until it can serve
		// the new one. MDM targets carry no bytes for us and pass through untouched.
		serveable := s.serveable(ctx, set, before)
		set = serveable
		published.replace(set)
		if first {
			first = false
			log.Printf("agent-update sync: first pull succeeded — %d target(s)", len(set))
		}
		// ★ THE MIGRATION MOMENT IS WORTH A WARNING. Handing authority to the control plane means its answer
		// REPLACES what this edge was serving — including when the answer is "nothing". That is the safe
		// direction (no device installs anything) and it is still a surprise: a fleet that was updating stops,
		// and the reason lives on a different machine from the one an operator would look at.
		if len(set) == 0 && len(before) > 0 {
			log.Printf("agent-update sync: ★ the control plane publishes NOTHING and this edge was publishing %d "+
				"target(s) — every device now reads \"nothing published\". The control plane is the authority now; "+
				"publish the release there (PUT /admin/agent-updates) to restore it", len(before))
		}
		for key, u := range set {
			if prev, had := before[key]; !had || prev.Manifest.Version != u.Manifest.Version {
				log.Printf("agent-update sync: %s now publishes %s (was %q)", key, u.Manifest.Version,
					prev.Manifest.Version)
			}
		}
	}
	pull()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pull()
		}
	}
}

// fetchArtifact pulls the bytes for a manifest this Edge publishes but does not hold.
//
// Verified against the manifest BEFORE the file appears under its real name: the device-facing route re-checks
// the digest anyway, and this keeps a failed or truncated transfer from ever occupying the path that route
// serves from — the same temp-then-rename rule endpoint staging uses, for the same reason.
func (s agentUpdateSource) fetchArtifact(ctx context.Context, m agentupdate.Manifest) error {
	name := artifactFileName(m.Platform, m.Arch, m.Version)
	if name == "" || strings.TrimSpace(s.artifactDir) == "" {
		return fmt.Errorf("no artifact directory on this edge")
	}
	url := fmt.Sprintf("%s/admin/agent-update-artifact?platform=%s&arch=%s",
		strings.TrimRight(s.url, "/"), m.Platform, m.Arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane answered HTTP %d%s", resp.StatusCode,
			agentupdate.DescribeHTTPErrorBody(resp.Body))
	}
	if err := os.MkdirAll(s.artifactDir, 0o750); err != nil {
		return err
	}
	// durable-write: staged — the artifact is streamed and hashed as it arrives (io.Copy through a MultiWriter
	// into sha256), so there is no []byte to hand durablefile.Write: holding a whole package in memory to
	// satisfy the shared writer would trade a real memory bound for a stylistic one. The REPLACE half still
	// goes through the package, which is the half that is platform-specific.
	tmp, err := os.CreateTemp(s.artifactDir, ".artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { tmp.Close(); os.Remove(tmpName) }()
	sum := sha256.New()
	written, cerr := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, m.ArtifactSize+1))
	if cerr != nil {
		return cerr
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if written != m.ArtifactSize || !strings.EqualFold(got, m.ArtifactSHA256) {
		return fmt.Errorf("the control plane served %d bytes sha256:%s and %s declares %d bytes sha256:%s",
			written, got, m.Version, m.ArtifactSize, m.ArtifactSHA256)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	tmp.Close()
	_ = os.Chmod(tmpName, 0o640)
	return os.Rename(tmpName, filepath.Join(s.artifactDir, name))
}

// buildAgentUpdateSourceClient trusts the control plane's CA, like the other CP→Edge syncs.
// requireHTTPSSource refuses a credential-bearing sync target that is not https.
//
// ★ THE TOKEN IS THE POINT (2026-08-12, fifth review). These pulls carry the admin bearer token, and the
// scheme was never checked: an http:// source URL would have put a broadly-privileged credential on the wire
// in clear, with the TLS config that looks like protection sitting unused beside it. Refused at STARTUP rather
// than at the first pull, because a process that runs while unable to do its job is the state this whole
// session has been removing.
func requireHTTPSSource(kind, rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("%s source URL %q is unparseable: %w", kind, rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s source URL %q is %q, not https: this pull carries the admin bearer token and will "+
			"not send it in clear", kind, rawURL, u.Scheme)
	}
	return nil
}

func buildAgentUpdateSourceClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile = strings.TrimSpace(caFile); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read the agent-update source CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the agent-update source CA %q has no usable certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		// ★ NO REDIRECTS AT ALL. Go's default follows up to ten and re-sends headers to the new host on a
		// same-host hop — and a control plane that has been talked into answering 302 is exactly the situation
		// where the admin token must not travel. There is no legitimate redirect on this path.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing to follow a redirect to %s while carrying the admin token", req.URL.Redacted())
		},
	}, nil
}

// refreshDeviceFacingPublished rebuilds the set GET /steer/agent-update-manifest answers from, out of what the
// admin store holds as ACTIVE for this tenant.
//
// Merged into the existing set rather than replacing it: this index is keyed by platform/arch with no tenant,
// so a second tenant's targets would otherwise disappear when the first publishes. That the index cannot tell
// two tenants' releases apart is a real limit and it is older than this function — recorded here because this
// is where a reader will next stand in front of it.
func refreshDeviceFacingPublished(deviceFacing *publishedUpdates, store *publishedAgentUpdateStore,
	tenantID string, trustedKeys []string) {
	// ★ A NIL DEVICE-FACING SET IS NOT A REASON TO GO QUIET (2026-08-13, thirtieth review #12). A publish that
	// gets this far has been stored durably, audited, and has raised the signing floor, and the caller has
	// already been told state=active — so returning here silently drops exactly the half that makes a release
	// reach a device. That is the "succeeds and vanishes" write path this repo has now found in four lanes; it
	// must at least be audible.
	//
	// Not fatal, because the state IS stored and an operator restarting with -agent-update-manifest-dir set will
	// serve it. Loud, because nothing else in the response says so.
	if deviceFacing == nil {
		log.Printf("★ agent_update_published_but_not_served tenant=%s: the release is stored and active, and this "+
			"process has nowhere to serve it from (-agent-update-manifest-dir is not set), so NO DEVICE will be "+
			"offered it until that is configured and this process restarts", tenantID)
		return
	}
	if store == nil {
		return
	}
	next := map[string]publishedUpdate{}
	for target, entry := range deviceFacing.targets() {
		next[target] = entry
	}
	now := time.Now().UTC()
	for target, env := range store.ForTenant(tenantID) {
		m, err := agentupdate.Open(env, trustedKeys, now)
		if err != nil {
			// Refusing to serve what this process cannot verify is the same rule the loader applies at boot.
			log.Printf("agent-update publish: %s is active in the store but does not verify here (%v) — devices "+
				"are NOT offered it", target, err)
			continue
		}
		next[target] = publishedUpdate{Manifest: m, Envelope: env, Source: "published via the admin API",
			TenantID: tenantID}
	}
	deviceFacing.replace(next)
	log.Printf("agent-update publish: the device-facing set now offers %d target(s)", len(next))
}

// decodeLimitedJSONBodyStrict additionally REFUSES a field the target type does not have.
//
// For a document this control plane is about to SIGN, an ignored field is the dangerous default: an operator
// who writes min_upgrade_from where the manifest says min_from gets a signed manifest without the constraint
// they asked for, and nothing anywhere says so. dsse-signupdate has always decoded strictly for the same
// reason; the server-side signing path must not be the lenient one.
func decodeLimitedJSONBodyStrict(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
