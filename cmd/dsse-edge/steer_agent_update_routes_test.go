package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func updateSigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func publishableManifest(now time.Time) agentupdate.Manifest {
	return agentupdate.Manifest{
		Schema:         agentupdate.SchemaVersion,
		Version:        "0.2.0",
		Platform:       agentupdate.PlatformWindows,
		Arch:           agentupdate.ArchAMD64,
		Channel:        "stable",
		Delivery:       agentupdate.DeliveryDSSE,
		ArtifactKind:   agentupdate.ArtifactKindMSI,
		ArtifactURL:    "https://packages.example.test/dsse-agent-0.2.0.msi",
		ArtifactSHA256: strings.Repeat("ab", 32),
		ArtifactSize:   4096,
		ReleasedAt:     now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:       now.Add(720 * time.Hour).Format(time.RFC3339),
	}
}

func publish(t *testing.T, dir, name string, sg *agentpolicy.Signer, m agentupdate.Manifest, now time.Time) {
	t.Helper()
	env, err := agentupdate.Sign(sg, m, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAPublishedManifestIsIndexedByPlatformAndArch(t *testing.T) {
	now := time.Now().UTC()
	dir, sg := t.TempDir(), updateSigner(t)
	publish(t, dir, "windows.json", sg, publishableManifest(now), now)

	p, err := loadPublishedUpdates(dir, []string{sg.PublicKeyHex()}, now)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if u, ok := p.forTarget("windows", "amd64"); !ok || u.Manifest.Version != "0.2.0" {
		t.Fatalf("forTarget(windows/amd64) = %+v ok=%t", u, ok)
	}
	// A device that asks for something nobody published gets nothing, not somebody else's build.
	if _, ok := p.forTarget("darwin", "arm64"); ok {
		t.Fatal("an unpublished target returned a manifest")
	}
}

// ★ A file this edge cannot verify must stop it starting. Publishing it would be refused by every device in
// the fleet at once, for a reason that reads as a key problem on thousands of endpoints and nowhere else — the
// cause would be one wrong file on one machine nobody is looking at.
func TestAManifestTheEdgeCannotVerifyIsRefusedAtLoad(t *testing.T) {
	now := time.Now().UTC()
	dir, sg := t.TempDir(), updateSigner(t)
	publish(t, dir, "windows.json", sg, publishableManifest(now), now)

	_, err := loadPublishedUpdates(dir, []string{updateSigner(t).PublicKeyHex()}, now)
	if err == nil {
		t.Fatal("a manifest signed by an unpinned key was published")
	}
	if !strings.Contains(err.Error(), "windows.json") {
		t.Fatalf("the error must name the file an operator has to fix, got %v", err)
	}
}

// An expired manifest is the same failure wearing different clothes: served happily, refused everywhere.
func TestAnExpiredManifestIsNotPublished(t *testing.T) {
	now := time.Now().UTC()
	dir, sg := t.TempDir(), updateSigner(t)
	m := publishableManifest(now)
	m.NotAfter = now.Add(-time.Minute).Format(time.RFC3339)
	publish(t, dir, "windows.json", sg, m, now.Add(-48*time.Hour))

	if _, err := loadPublishedUpdates(dir, []string{sg.PublicKeyHex()}, now); err == nil {
		t.Fatal("an expired manifest was published")
	}
}

// ★ Which build a fleet receives must not depend on filename order.
func TestTwoManifestsForOneTargetAreRefusedRatherThanRanked(t *testing.T) {
	now := time.Now().UTC()
	dir, sg := t.TempDir(), updateSigner(t)
	publish(t, dir, "a-windows.json", sg, publishableManifest(now), now)
	second := publishableManifest(now)
	second.Version = "0.3.0"
	publish(t, dir, "b-windows.json", sg, second, now)

	_, err := loadPublishedUpdates(dir, []string{sg.PublicKeyHex()}, now)
	if err == nil {
		t.Fatal("two manifests for one target were silently ranked")
	}
	for _, want := range []string{"0.2.0", "0.3.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name both candidates so the operator knows which to remove, got %v", err)
		}
	}
}

// ★ No pin, no publishing. An edge handing out documents it cannot check would fail to notice the wrong one,
// which is the only failure this load-time check exists to catch.
func TestPublishingWithoutAPinIsRefused(t *testing.T) {
	if _, err := loadPublishedUpdates(t.TempDir(), nil, time.Now()); err == nil {
		t.Fatal("an edge with no pinned update key agreed to publish")
	}
}

// A directory with nothing in it is not an error: an edge that publishes nothing is the normal state, and
// devices read it as "nothing published".
func TestAnEmptyPublicationDirectoryIsNotAFailure(t *testing.T) {
	p, err := loadPublishedUpdates(t.TempDir(), []string{updateSigner(t).PublicKeyHex()}, time.Now())
	if err != nil {
		t.Fatalf("an empty directory must not be an error: %v", err)
	}
	if _, ok := p.forTarget("windows", "amd64"); ok {
		t.Fatal("something was published from an empty directory")
	}
}

// The Edge must never be able to mint one of these. Stated as a test because the tempting change — "sign it
// here like every other document on this surface" — would make every traffic node a release-authoring machine.
func TestTheEdgeHasNoWayToSignAnUpdateManifest(t *testing.T) {
	body, err := os.ReadFile("steer_agent_update_routes.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "agentupdate.Sign(") {
		t.Fatal("this file signs an update manifest; the update key must never be usable from a traffic node")
	}
}
