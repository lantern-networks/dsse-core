package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// admin_agent_update_publish_test.go — the three properties a review asked to see asserted, because each of
// them had a period in this repo where it was false and nothing said so.

// signedUpdate builds a manifest over REAL bytes: the digest and size describe artifactBytesFor(version), so a
// test can put the actual artifact on disk. The edge and the control plane both verify the digest now, so a
// placeholder of the right name is (correctly) rejected — a manifest naming bytes nobody has is not a release.
func artifactBytesFor(version string) []byte { return []byte("artifact bytes for " + version) }

func signedUpdate(t *testing.T, sg *agentpolicy.Signer, version string, now time.Time) (agentupdate.Manifest,
	agentpolicy.Envelope) {
	t.Helper()
	m := publishableManifest(now)
	m.Version = version
	body := artifactBytesFor(version)
	sum := sha256.Sum256(body)
	m.ArtifactSHA256 = hex.EncodeToString(sum[:])
	m.ArtifactSize = int64(len(body))
	env, err := agentupdate.Sign(sg, m, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return m, env
}

func pinnedKey(t *testing.T, sg *agentpolicy.Signer) string {
	t.Helper()
	return sg.PublicKeyHex()
}

// ★ ONE TENANT'S ADMIN MUST NOT BE ABLE TO CHANGE ANOTHER TENANT'S RELEASE (2026-08-12, fifth review). The
// published set was keyed platform/arch alone, so `admin.agents.write` — a TENANT-scoped role — reached every
// tenant's fleet: publishing for darwin/arm64 in tenant A replaced what tenant B's devices were offered. The
// blast radius of that is "which signed code runs on somebody else's machines", so it gets a test rather than
// a comment.
func TestPublishedReleasesAreScopedToTheirTenant(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	store := newPublishedAgentUpdateStore()

	_, envA := signedUpdate(t, sg, "0.2.0", now)
	_, envB := signedUpdate(t, sg, "0.9.9", now)
	bytesHere := func(agentupdate.Manifest) bool { return true }
	if _, _, _, err := store.Publish("tenant_a", envA, keys, now, bytesHere); err != nil {
		t.Fatalf("publish for tenant_a: %v", err)
	}
	if _, _, _, err := store.Publish("tenant_b", envB, keys, now, bytesHere); err != nil {
		t.Fatalf("publish for tenant_b: %v", err)
	}

	a := store.ForTenant("tenant_a")
	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)
	if len(a) != 1 {
		t.Fatalf("tenant_a should see exactly its own target, saw %d", len(a))
	}
	gotA, err := agentupdate.Open(a[key], keys, now)
	if err != nil {
		t.Fatalf("open tenant_a's envelope: %v", err)
	}
	if gotA.Version != "0.2.0" {
		t.Fatalf("tenant_b's publication reached tenant_a: got %s, want 0.2.0", gotA.Version)
	}
	gotB, err := agentupdate.Open(store.ForTenant("tenant_b")[key], keys, now)
	if err != nil {
		t.Fatalf("open tenant_b's envelope: %v", err)
	}
	if gotB.Version != "0.9.9" {
		t.Fatalf("tenant_b lost its own publication: got %s", gotB.Version)
	}
	if n := len(store.ForTenant("tenant_c")); n != 0 {
		t.Fatalf("a tenant nobody published for should see nothing, saw %d", n)
	}
}

// A store written before the keys carried a tenant must not read back as "nothing published" — the fix would
// otherwise unpublish every fleet on its first restart, which is the outage it exists to prevent.
//
// ★ AND NOT INTO ONE TENANT EITHER (2026-08-12, sixth review). Those entries used to be answered to EVERY
// tenant. Adopting them into the control plane's own tenant is right for a single-tenant deployment and
// silently wrong for a multi-tenant one: every other tenant would read "nothing published" after the upgrade.
// They are a READ-ONLY GLOBAL FALLBACK, shadowed the moment a tenant publishes its own.
func TestPreTenantEntriesAreAReadOnlyGlobalFallback(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	_, env := signedUpdate(t, sg, "0.2.7", now)
	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)

	path := filepath.Join(t.TempDir(), "agent_updates.json")
	b, _ := json.Marshal(map[string]agentpolicy.Envelope{key: env})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newPublishedAgentUpdateStore()
	if err := store.LoadFrom(path, "tenant_a"); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Every tenant still sees it, which is what it saw before the keys carried a tenant.
	for _, tenant := range []string{"tenant_a", "tenant_b", "tenant_never_heard_of"} {
		got, oerr := agentupdate.Open(store.ForTenant(tenant)[key], keys, now)
		if oerr != nil || got.Version != "0.2.7" {
			t.Fatalf("%s lost the pre-tenant release: %v %s", tenant, oerr, got.Version)
		}
	}
	// And publishing shadows it for that tenant only.
	_, envB := signedUpdate(t, sg, "0.9.9", now)
	if _, _, _, err := store.Publish("tenant_b", envB, keys, now,
		func(agentupdate.Manifest) bool { return true }); err != nil {
		t.Fatalf("publish for tenant_b: %v", err)
	}
	gotB, _ := agentupdate.Open(store.ForTenant("tenant_b")[key], keys, now)
	if gotB.Version != "0.9.9" {
		t.Fatalf("tenant_b's own release did not shadow the fallback: %s", gotB.Version)
	}
	gotA, _ := agentupdate.Open(store.ForTenant("tenant_a")[key], keys, now)
	if gotA.Version != "0.2.7" {
		t.Fatalf("tenant_b's publication changed what tenant_a is served: %s", gotA.Version)
	}
}

// ★ THE PULL CARRIES THE ADMIN BEARER TOKEN. An http:// source URL would put it on the wire in clear, and the
// failure is silent — the sync works, so nothing ever looks wrong.
func TestASourceURLMustBeHTTPS(t *testing.T) {
	if err := requireHTTPSSource("agent-update", "http://cp.example.test"); err == nil {
		t.Fatalf("an http:// source was accepted")
	}
	if err := requireHTTPSSource("agent-update", "https://cp.example.test"); err != nil {
		t.Fatalf("an https:// source was refused: %v", err)
	}
}

// ★ AN EDGE PUBLISHES ONLY WHAT IT CAN HAND OVER. When the control plane publishes a release whose artifact
// this edge neither holds nor can fetch, the devices must keep being offered the release it CAN serve — not a
// version whose bytes answer 404.
func TestAnUnfetchableArtifactKeepsThePreviousRelease(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	old, oldEnv := signedUpdate(t, sg, "0.2.4", now)
	_, newEnv := signedUpdate(t, sg, "0.2.5", now)

	artifactDir := t.TempDir()
	// The old release's bytes are here — and they must be the REAL ones now: the edge verifies size and digest
	// before adopting, so a placeholder of the right name would (correctly) be rejected and refetched.
	if err := os.WriteFile(filepath.Join(artifactDir,
		artifactFileName(old.Platform, old.Arch, old.Version)), artifactBytesFor(old.Version), 0o600); err != nil {
		t.Fatal(err)
	}

	serving := newEnv
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/agent-update-artifact") {
			http.Error(w, "the artifact is not here", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": "tenant_a",
			"envelopes": map[string]agentpolicy.Envelope{
				updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64): serving,
			},
		})
	}))
	defer cp.Close()

	src := agentUpdateSource{url: cp.URL, token: "t", trustedKeys: keys, artifactDir: artifactDir,
		interval: time.Hour, client: cp.Client(), tenantID: "tenant_a"}
	published := &publishedUpdates{byTarget: map[string]publishedUpdate{}}

	// First: the control plane publishes the release whose bytes ARE here.
	serving = oldEnv
	set, err := src.fetch(context.Background(), now)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	published.replace(applySeveableForTest(t, src, set, published.targets()))
	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)
	if got := published.targets()[key].Manifest.Version; got != "0.2.4" {
		t.Fatalf("the servable release was not adopted: %q", got)
	}

	// Then: it publishes one this edge cannot fetch. The device-facing answer must not change.
	serving = newEnv
	set, err = src.fetch(context.Background(), now)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	published.replace(applySeveableForTest(t, src, set, published.targets()))
	if got := published.targets()[key].Manifest.Version; got != "0.2.4" {
		t.Fatalf("an unfetchable release was published to devices: %q (want the previous 0.2.4)", got)
	}
}

// ★ AN EDGE MUST NOT OFFER ANOTHER TENANT'S BUILD. A token scoped to the wrong tenant, or a URL pointing at
// the wrong control plane, ends with the wrong signed code on these devices — so the answer names the tenant
// it is for and the edge checks it.
func TestAPublishedSetForAnotherTenantIsRefused(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	_, env := signedUpdate(t, sg, "0.2.5", now)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": "tenant_b",
			"envelopes": map[string]agentpolicy.Envelope{
				updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64): env,
			},
		})
	}))
	defer cp.Close()

	src := agentUpdateSource{url: cp.URL, token: "t", trustedKeys: []string{pinnedKey(t, sg)},
		interval: time.Hour, client: cp.Client(), tenantID: "tenant_a"}
	if _, err := src.fetch(context.Background(), now); err == nil {
		t.Fatalf("another tenant's published set was adopted")
	} else if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// applySeveableForTest runs the same "only what this edge can hand over" filter the sync loop applies, so the
// test exercises the rule rather than a copy of it.
func applySeveableForTest(t *testing.T, s agentUpdateSource, set, before map[string]publishedUpdate) map[string]publishedUpdate {
	t.Helper()
	return s.serveable(context.Background(), set, before)
}

// ★ A MANIFEST WITHOUT ITS BYTES IS NOT A RELEASE. Publishing used to replace the active entry immediately, so
// between the manifest PUT and the artifact PUT the control plane offered a version whose bytes answered 404.
// The ordering cannot be reversed — bytes are only checkable against the manifest that names their digest — so
// the manifest is held pending and the artifact upload activates it.
func TestAReleaseIsPendingUntilItsArtifactArrives(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	store := newPublishedAgentUpdateStore()
	if err := store.LoadFrom(filepath.Join(t.TempDir(), "agent_updates.json"), "tenant_a"); err != nil {
		t.Fatal(err)
	}
	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)

	// The release already being served: its bytes are here.
	_, oldEnv := signedUpdate(t, sg, "0.2.4", now)
	if _, active, _, err := store.Publish("tenant_a", oldEnv, keys, now,
		func(agentupdate.Manifest) bool { return true }); err != nil || !active {
		t.Fatalf("publish 0.2.4: active=%t err=%v", active, err)
	}

	// The new one: no bytes yet.
	_, newEnv := signedUpdate(t, sg, "0.2.5", now)
	_, active, _, err := store.Publish("tenant_a", newEnv, keys, now, func(agentupdate.Manifest) bool { return false })
	if err != nil {
		t.Fatalf("publish 0.2.5: %v", err)
	}
	if active {
		t.Fatalf("a release with no artifact went active")
	}
	served, oerr := agentupdate.Open(store.ForTenant("tenant_a")[key], keys, now)
	if oerr != nil {
		t.Fatalf("open the active envelope: %v", oerr)
	}
	if served.Version != "0.2.4" {
		t.Fatalf("the fleet was moved to a release with no bytes: %s", served.Version)
	}
	if p := store.PendingFor("tenant_a"); len(p) != 1 {
		t.Fatalf("the new release is not visible as pending: %d", len(p))
	}

	// The bytes land.
	promoted, aerr := store.Activate("tenant_a", agentupdate.PlatformWindows, agentupdate.ArchAMD64,
		newEnv.PayloadSHA256)
	if aerr != nil || !promoted {
		t.Fatalf("activate: promoted=%t err=%v", promoted, aerr)
	}
	served, _ = agentupdate.Open(store.ForTenant("tenant_a")[key], keys, now)
	if served.Version != "0.2.5" {
		t.Fatalf("the artifact arrived and the release did not activate: %s", served.Version)
	}
	if len(store.PendingFor("tenant_a")) != 0 {
		t.Fatalf("an activated release is still pending")
	}

	// And it survives a restart in the same state.
	reread := newPublishedAgentUpdateStore()
	if err := reread.LoadFrom(store.path, "tenant_a"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	back, berr := agentupdate.Open(reread.ForTenant("tenant_a")[key], keys, now)
	if berr != nil || back.Version != "0.2.5" {
		t.Fatalf("the activation did not survive a restart: %v %s", berr, back.Version)
	}
}

// ★ THE ENVELOPES WERE SCOPED AND THE BYTES WERE NOT. Two tenants publishing "0.2.7" — the normal case, since
// everyone runs the same version numbers — wrote to one file and overwrote each other's signed artifact.
func TestArtifactPathsAreScopedPerTenant(t *testing.T) {
	dir := t.TempDir()
	a := artifactStorePath(dir, "tenant_a", "darwin", "arm64", "0.2.7")
	b := artifactStorePath(dir, "tenant_b", "darwin", "arm64", "0.2.7")
	if a == "" || b == "" {
		t.Fatalf("a valid target produced no path: %q %q", a, b)
	}
	if a == b {
		t.Fatalf("two tenants share one artifact path (%s): one overwrites the other's signed bytes", a)
	}
	// A caller with no tenant must not be able to address a flat, shared path.
	if p := artifactStorePath(dir, "", "darwin", "arm64", "0.2.7"); p != "" {
		t.Fatalf("an unscoped caller got a path: %s", p)
	}
	if p := artifactStorePath(dir, "../escape", "darwin", "arm64", "0.2.7"); p != "" {
		t.Fatalf("a traversing tenant id produced a path: %s", p)
	}
}

// ★ SIZE IS NOT AN IDENTITY. "The bytes are here" was decided by a stat, so a leftover file of the same length
// activated a release over bytes nothing had checked.
func TestArtifactBytesMustMatchTheDigestNotJustTheSize(t *testing.T) {
	now := time.Now().UTC()
	m, _ := signedUpdate(t, updateSigner(t), "0.2.7", now)
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")

	real := artifactBytesFor("0.2.7")
	if err := os.WriteFile(path, real, 0o600); err != nil {
		t.Fatal(err)
	}
	if !artifactBytesMatch(path, m) {
		t.Fatalf("the real artifact was rejected")
	}
	// Same length, different bytes — what a stat cannot tell apart.
	impostor := make([]byte, len(real))
	copy(impostor, real)
	impostor[0] ^= 0xff
	if err := os.WriteFile(path, impostor, 0o600); err != nil {
		t.Fatal(err)
	}
	if artifactBytesMatch(path, m) {
		t.Fatalf("a file of the right SIZE passed as the artifact")
	}
}

// ★ AN UPLOAD MUST ACTIVATE THE MANIFEST ITS BYTES WERE CHECKED AGAINST. A second publish while a large
// artifact is streaming would otherwise let A's bytes activate B, whose artifact is not here at all.
func TestAnUploadCannotActivateAManifestItDidNotVerify(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	store := newPublishedAgentUpdateStore()
	_, envA := signedUpdate(t, sg, "0.2.5", now)
	_, envB := signedUpdate(t, sg, "0.2.6", now)

	noBytes := func(agentupdate.Manifest) bool { return false }
	if _, _, _, err := store.Publish("tenant_a", envA, keys, now, noBytes); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	// The upload for A begins here, verifying against envA… and B is published while it streams.
	if _, _, _, err := store.Publish("tenant_a", envB, keys, now, noBytes); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	activated, err := store.Activate("tenant_a", agentupdate.PlatformWindows, agentupdate.ArchAMD64,
		envA.PayloadSHA256)
	if err == nil {
		t.Fatalf("A's bytes activated the pending release (activated=%t): B has no artifact at all", activated)
	}
	if activated {
		t.Fatalf("refused and activated at the same time")
	}
	if len(store.ForTenant("tenant_a")) != 0 {
		t.Fatalf("something went active despite the refusal")
	}
}

// ★ NO ARTIFACT DIRECTORY IS NOT "EVERYTHING IS FINE". An edge without -agent-update-manifest-dir used to adopt
// every DSSE release and then answer 404 to every device that asked for the bytes.
func TestAnEdgeWithNoArtifactDirectoryDoesNotAdoptDSSEReleases(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	m, env := signedUpdate(t, sg, "0.2.5", now)
	src := agentUpdateSource{trustedKeys: []string{pinnedKey(t, sg)}, artifactDir: ""}
	key := updateTargetKey(m.Platform, m.Arch)
	set := map[string]publishedUpdate{key: {Manifest: m, Envelope: env}}

	got := src.serveable(context.Background(), set, map[string]publishedUpdate{})
	if len(got) != 0 {
		t.Fatalf("an edge that cannot hand over bytes adopted the release anyway: %+v", got)
	}

	// MDM carries no bytes for us, so it is unaffected.
	mdm := m
	mdm.Delivery = agentupdate.DeliveryMDM
	got = src.serveable(context.Background(), map[string]publishedUpdate{key: {Manifest: mdm, Envelope: env}},
		map[string]publishedUpdate{})
	if len(got) != 1 {
		t.Fatalf("an MDM release was dropped for want of an artifact directory this lane never uses")
	}
}

// ★★ EVERY TENANT COMES BACK, NOT JUST THIS EDGE'S (2026-08-13, thirtieth review #10). The twenty-ninth
// review's fix reseeded the device-facing set from the durable store at boot — for the bundle tenant alone. On
// a multi-tenant control plane every other tenant's API-published release stayed un-offered after a restart,
// with the admin screen showing "active" and devices getting 404: the exact symptom that fix was written to
// end, for everyone except the tenant it was tested with.
func TestTheDurableStoreNamesEveryTenantItHoldsAReleaseFor(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	keys := []string{pinnedKey(t, sg)}
	store := newPublishedAgentUpdateStore()
	bytesHere := func(agentupdate.Manifest) bool { return true }

	_, envA := signedUpdate(t, sg, "0.2.0", now)
	_, envB := signedUpdate(t, sg, "0.9.9", now)
	if _, _, _, err := store.Publish("tenant_a", envA, keys, now, bytesHere); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Publish("tenant_b", envB, keys, now, bytesHere); err != nil {
		t.Fatal(err)
	}

	got := store.Tenants()
	if len(got) != 2 || got[0] != "tenant_a" || got[1] != "tenant_b" {
		t.Fatalf("the boot reseed would visit %v — a tenant missing here is a fleet that gets 404 after every "+
			"restart while its screen says active", got)
	}
	if n := len(newPublishedAgentUpdateStore().Tenants()); n != 0 {
		t.Fatalf("an empty store named %d tenants", n)
	}
}
