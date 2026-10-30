package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

func TestCaseDistinctPublishedUpdateAndArtifactScopes(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	store := newPublishedAgentUpdateStore().WithArtifactDir(t.TempDir())
	_, upper := signedUpdate(t, signer, "0.4.1", now)
	_, lower := signedUpdate(t, signer, "0.4.2", now)
	ready := func(agentupdate.Manifest) bool { return true }
	for _, tc := range []struct {
		tenant     string
		envVersion string
	}{{"Acme", "0.4.1"}, {"acme", "0.4.2"}} {
		env := upper
		if tc.tenant == "acme" {
			env = lower
		}
		if _, _, _, err := store.Publish(tc.tenant, env, keys, now, ready); err != nil {
			t.Fatal(err)
		}
	}
	target := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)
	for _, tc := range []struct{ tenant, version string }{{"Acme", "0.4.1"}, {"acme", "0.4.2"}} {
		env := store.ForTenant(tc.tenant)[target]
		m, err := agentupdate.Open(env, keys, now)
		if err != nil || m.Version != tc.version {
			t.Fatalf("%s received %q, %v", tc.tenant, m.Version, err)
		}
		if got := store.CountForTenant(tc.tenant); got != 1 {
			t.Fatalf("%s count = %d", tc.tenant, got)
		}
	}
	if artifactBlobKey("Acme", "windows", "amd64", "0.4.1") == artifactBlobKey("acme", "windows", "amd64", "0.4.1") {
		t.Fatal("case-distinct tenant artifacts share the same blob key")
	}
	upperPath := artifactStorePath(store.artifactDir, "Acme", "windows", "amd64", "0.4.1")
	lowerPath := artifactStorePath(store.artifactDir, "acme", "windows", "amd64", "0.4.1")
	if upperPath == lowerPath {
		t.Fatal("case-distinct tenant artifacts share the same local path")
	}
	for _, p := range []string{upperPath, lowerPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("private package"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.RemoveTenantChecked("Acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lowerPath); err != nil {
		t.Fatalf("acme package erased with Acme: %v", err)
	}
	if got := store.CountForTenant("acme"); got != 1 {
		t.Fatalf("acme publication erased with Acme: %d", got)
	}
}

func TestCaseDistinctSigningFloors(t *testing.T) {
	r := newAgentUpdateSignRatchet(t.TempDir())
	if err := r.Record("Acme", "windows", "amd64", "0.4.9"); err != nil {
		t.Fatal(err)
	}
	if got := r.FloorsForTenant("acme"); len(got) != 0 {
		t.Fatalf("other tenant saw signing floor: %#v", got)
	}
	if err := r.Check("acme", "windows", "amd64", "0.4.1"); err != nil {
		t.Fatalf("other tenant's floor blocked signing: %v", err)
	}
	if err := r.Record("acme", "windows", "amd64", "0.4.2"); err != nil {
		t.Fatal(err)
	}
	if r.FloorsForTenant("Acme")["windows/amd64"] != "0.4.9" || r.FloorsForTenant("acme")["windows/amd64"] != "0.4.2" {
		t.Fatal("case-distinct signing floors did not remain separate")
	}
}

func TestCaseDistinctDeviceFacingPublicationSurvivesRefresh(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	store := newPublishedAgentUpdateStore()
	_, upper := signedUpdate(t, signer, "0.4.1", now)
	_, lower := signedUpdate(t, signer, "0.4.2", now)
	if _, _, _, err := store.Publish("Acme", upper, keys, now, func(agentupdate.Manifest) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Publish("acme", lower, keys, now, func(agentupdate.Manifest) bool { return true }); err != nil {
		t.Fatal(err)
	}
	deviceFacing := &publishedUpdates{byTarget: map[string]publishedUpdate{}}
	refreshDeviceFacingPublished(deviceFacing, store, "Acme", keys)
	refreshDeviceFacingPublished(deviceFacing, store, "acme", keys)
	if len(deviceFacing.targets()) != 2 {
		t.Fatalf("two case-distinct tenant canaries collapsed into %d device-facing entries", len(deviceFacing.targets()))
	}
}
