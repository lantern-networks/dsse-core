package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
)

// memoryBlob is one row of the deployment's shared state, standing in for Postgres. Two stores handed the SAME
// memoryBlob are two control planes of one deployment — which is the only way to write a test that fails for
// the reason this file exists.
type memoryBlob struct {
	mu   sync.Mutex
	data []byte
	fail bool
}

func (b *memoryBlob) Load() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return nil, errors.New("the shared store is unreachable")
	}
	return append([]byte(nil), b.data...), nil
}

func (b *memoryBlob) Save(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("the shared store is unreachable")
	}
	b.data = append([]byte(nil), data...)
	return nil
}

// ★★★ THE PUBLISHED SET WAS PER NODE, IN AN HA PAIR (2026-08-28, measured on the two-region lab). region-a's
// control plane held `deployment|darwin/arm64` and region-b's had no file at all: it never received the
// publish, and it loads its own disk at start-up. The front door balances both, so an Edge polling every
// minute was told 1 target, then 0, then 1 — and said "the control plane publishes NOTHING and this edge was
// publishing 1 target(s)" about a control plane that was simply the other one.
func TestThePublishedSetBelongsToTheDeploymentNotTheNodeThatServedThePublish(t *testing.T) {
	shared := &memoryBlob{}

	served := newPublishedAgentUpdateStore()
	if err := served.LoadFromPersister(shared, "tenant_kaede"); err != nil {
		t.Fatalf("load the node that serves the publish: %v", err)
	}
	if err := served.persistLocked(map[string]agentpolicy.Envelope{
		tenantTargetKey(agentUpdateCatalogueScope, "darwin", "arm64"): {PayloadSHA256: "published-here"},
	}, map[string]agentpolicy.Envelope{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// The other control plane of the same deployment, starting from nothing of its own.
	other := newPublishedAgentUpdateStore()
	if err := other.LoadFromPersister(shared, "tenant_kaede"); err != nil {
		t.Fatalf("load the other control plane: %v", err)
	}
	if got := other.ForTenant("tenant_kaede")["darwin/arm64"].PayloadSHA256; got != "published-here" {
		t.Fatalf("the second control plane answers %q for a release the first published — a device polling the "+
			"front door is told a release exists, then that nothing is published, on alternate minutes", got)
	}
}

// ★★★ AND SO WERE THE BYTES. A shared catalogue over node-local artifacts is worse than the split it replaces:
// every node NAMES the release and only one can hand it over, so the manifest becomes a promise the deployment
// breaks on half its downloads.
func TestArtifactBytesReachAControlPlaneThatNeverServedTheUpload(t *testing.T) {
	shelved := map[string]*memoryBlob{}
	var mu sync.Mutex
	shelf := &agentUpdateArtifactShelf{open: func(key string) blobstore.Persister {
		mu.Lock()
		defer mu.Unlock()
		if shelved[key] == nil {
			shelved[key] = &memoryBlob{}
		}
		return shelved[key]
	}}

	uploadDir := t.TempDir()
	served := newPublishedAgentUpdateStore().WithArtifactDir(uploadDir).WithArtifactShelf(shelf)
	local := artifactStorePath(uploadDir, agentUpdateCatalogueScope, "darwin", "arm64", "0.3.0")
	if err := os.MkdirAll(filepath.Dir(local), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("the installer"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := served.shelveArtifact(local, agentUpdateCatalogueScope, "darwin", "arm64", "0.3.0"); err != nil {
		t.Fatalf("shelve: %v", err)
	}

	// The control that says this test measures the shelf and not something else: the same node without one
	// cannot produce the bytes, which is what every control plane but the uploader's did before this.
	otherDir := t.TempDir()
	unshelved := newPublishedAgentUpdateStore().WithArtifactDir(otherDir)
	if _, err := os.ReadFile(unshelved.artifactPathFor(otherDir, "tenant_kaede", "darwin", "arm64", "0.3.0")); err == nil {
		t.Fatal("a control plane with no shared shelf produced the bytes anyway — this test is measuring " +
			"something other than the shelf")
	}

	other := newPublishedAgentUpdateStore().WithArtifactDir(otherDir).WithArtifactShelf(shelf)
	path := other.artifactPathFor(otherDir, "tenant_kaede", "darwin", "arm64", "0.3.0")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the control plane that did not serve the upload cannot hand over the release: %v — this is the "+
			"404 a device gets when the front door picks the other node", err)
	}
	if string(got) != "the installer" {
		t.Fatalf("filled the wrong bytes: %q", got)
	}
}

// ★ A SHELVING FAILURE MUST NOT ACTIVATE. Bytes that reached one node are not a release the fleet can fetch.
func TestBytesThatDidNotReachTheShelfAreReportedAsAFailure(t *testing.T) {
	shelf := &agentUpdateArtifactShelf{open: func(string) blobstore.Persister { return &memoryBlob{fail: true} }}
	dir := t.TempDir()
	store := newPublishedAgentUpdateStore().WithArtifactDir(dir).WithArtifactShelf(shelf)
	local := artifactStorePath(dir, agentUpdateCatalogueScope, "darwin", "arm64", "0.3.0")
	if err := os.MkdirAll(filepath.Dir(local), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := store.shelveArtifact(local, agentUpdateCatalogueScope, "darwin", "arm64", "0.3.0"); err == nil {
		t.Fatal("shelving onto an unreachable shared store answered nil — the upload route would activate a " +
			"release only this node can serve")
	}
}

// ★★★ A HALT ON ONE CONTROL PLANE IS NOT A HALT. Same shape, one store over: an operator freezing a rollout
// wrote one node's disk, and the Edge polling the front door was answered "frozen", then "not frozen".
func TestTheHaltAndTheDesiredVersionAreTheDeploymentsToo(t *testing.T) {
	shared := &memoryBlob{}
	halted := agentrollout.NewAgentRolloutStore()
	if err := halted.LoadFromPersister(shared); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := halted.Set("tenant_kaede", agentrollout.AgentRolloutPlan{Frozen: true, Reason: "incident"}); err != nil {
		t.Fatalf("halt: %v", err)
	}

	other := agentrollout.NewAgentRolloutStore()
	if err := other.LoadFromPersister(shared); err != nil {
		t.Fatalf("load the other control plane: %v", err)
	}
	if !other.Get("tenant_kaede").Frozen {
		t.Fatal("the second control plane answers \"not frozen\" for a fleet somebody halted — and an edge " +
			"cannot tell that from the halt being lifted")
	}
}

// ★ WHAT AN ORGANIZATION WAS TOLD TO RUN IS COUNTED, AND ERASED WITH IT. Both stores were invisible to the
// footprint until the day they moved to shared state; a store nobody counts contributes nothing to "what is
// left", so an erasure over it answers complete=true whatever it still holds.
func TestDeletingAnOrganizationTakesItsPlanAndItsOwnReleases(t *testing.T) {
	plans := agentrollout.NewAgentRolloutStore()
	if err := plans.Set("tenant_kaede", agentrollout.AgentRolloutPlan{DesiredVersion: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if got := plans.CountForTenant("tenant_kaede"); got != 1 {
		t.Fatalf("the organization's plan counts %d", got)
	}

	dir := t.TempDir()
	releases := newPublishedAgentUpdateStore().WithArtifactDir(dir)
	releases.envelopes[tenantTargetKey("tenant_kaede", "darwin", "arm64")] = agentpolicy.Envelope{PayloadSHA256: "canary"}
	releases.envelopes[tenantTargetKey(agentUpdateCatalogueScope, "darwin", "arm64")] = agentpolicy.Envelope{PayloadSHA256: "catalogue"}
	bytes := artifactStorePath(dir, "tenant_kaede", "darwin", "arm64", "0.3.0")
	if err := os.MkdirAll(filepath.Dir(bytes), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bytes, []byte("their build"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := releases.CountForTenant("tenant_kaede"); got != 1 {
		t.Fatalf("the organization's own shelf counts %d", got)
	}
	if got := releases.CountForTenant(agentUpdateCatalogueScope); got != 0 {
		t.Fatalf("the deployment's catalogue is counted as some organization's: %d", got)
	}

	if got := plans.RemoveTenant("tenant_kaede"); got != 1 {
		t.Fatalf("erasing the plan reported %d", got)
	}
	if got := releases.RemoveTenant("tenant_kaede"); got != 1 {
		t.Fatalf("erasing their releases reported %d", got)
	}
	if _, err := os.Stat(bytes); !os.IsNotExist(err) {
		t.Fatal("the build published to that organization is still on disk after the erasure said it was gone")
	}
	// ★ AND THE CATALOGUE SURVIVES. A customer leaving does not unpublish the build every other customer takes.
	if got := releases.ForTenant("tenant_other")["darwin/arm64"].PayloadSHA256; got != "catalogue" {
		t.Fatalf("deleting one organization removed the deployment's catalogue: %q", got)
	}
}

// ★★★ A DEPLOYMENT THAT WAS ALREADY PUBLISHING KEEPS ITS DOWNLOADS (2026-08-28). The manifests migrate to
// shared state through postgres+import; the bytes had nowhere to migrate through, so every release published
// before the shelf existed would have been NAMED by both control planes and SERVED by neither. Each node puts
// what it holds onto the shelf once, at start-up — and only bytes that are the ones the published manifest
// names, which is what makes it a migration rather than a way to distribute the wrong build.
func TestReleasesPublishedBeforeTheShelfExistedAreStillServable(t *testing.T) {
	shelved := map[string]*memoryBlob{}
	var mu sync.Mutex
	shelf := &agentUpdateArtifactShelf{open: func(key string) blobstore.Persister {
		mu.Lock()
		defer mu.Unlock()
		if shelved[key] == nil {
			shelved[key] = &memoryBlob{}
		}
		return shelved[key]
	}}
	now := time.Now().UTC()
	signer := updateSigner(t)
	m, env := signedUpdate(t, signer, "0.2.4", now)

	dir := t.TempDir()
	held := newPublishedAgentUpdateStore().WithArtifactDir(dir).WithArtifactShelf(shelf)
	held.envelopes[tenantTargetKey(agentUpdateCatalogueScope, m.Platform, m.Arch)] = env
	path := artifactStorePath(dir, agentUpdateCatalogueScope, m.Platform, m.Arch, m.Version)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, artifactBytesFor("0.2.4"), 0o640); err != nil {
		t.Fatal(err)
	}
	if seeded := held.SeedShelfFromDisk(dir, []string{signer.PublicKeyHex()}, now); seeded != 1 {
		t.Fatalf("seeded %d release(s) from this node's disk, wanted 1", seeded)
	}

	// The other control plane, which never saw the upload, can now serve it.
	otherDir := t.TempDir()
	other := newPublishedAgentUpdateStore().WithArtifactDir(otherDir).WithArtifactShelf(shelf)
	got, err := os.ReadFile(other.artifactPathFor(otherDir, "tenant_kaede", m.Platform, m.Arch, m.Version))
	if err != nil {
		t.Fatalf("the release that was published before the shelf existed cannot be served: %v", err)
	}
	if string(got) != string(artifactBytesFor("0.2.4")) {
		t.Fatalf("wrong bytes: %q", got)
	}
}

// ★ AND BYTES THAT ARE NOT THE ONES THE MANIFEST NAMES ARE NOT SEEDED. A node holding a stale or half-written
// file must not be able to make it the deployment's copy.
func TestSeedingRefusesBytesThePublishedManifestDoesNotName(t *testing.T) {
	shelf := &agentUpdateArtifactShelf{open: func(string) blobstore.Persister { return &memoryBlob{} }}
	now := time.Now().UTC()
	signer := updateSigner(t)
	m, env := signedUpdate(t, signer, "0.2.4", now)

	dir := t.TempDir()
	store := newPublishedAgentUpdateStore().WithArtifactDir(dir).WithArtifactShelf(shelf)
	store.envelopes[tenantTargetKey(agentUpdateCatalogueScope, m.Platform, m.Arch)] = env
	path := artifactStorePath(dir, agentUpdateCatalogueScope, m.Platform, m.Arch, m.Version)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("a different build of the same version"), 0o640); err != nil {
		t.Fatal(err)
	}
	if seeded := store.SeedShelfFromDisk(dir, []string{signer.PublicKeyHex()}, now); seeded != 0 {
		t.Fatalf("seeded %d release(s) whose bytes the manifest does not name", seeded)
	}
}
