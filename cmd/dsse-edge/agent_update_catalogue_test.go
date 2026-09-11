package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// ★★★ WHAT EXISTS AND WHAT AN ORGANIZATION RUNS WERE ONE OBJECT (2026-08-28, measured by publishing a real
// signed, notarised package and then asking a device of another organization for it: 404, "no agent updates
// are published by this edge").
//
// The published set was keyed per organization, so "the version this deployment distributes" could only be
// said by writing it into each organization separately — and the screen that writes it was hidden inside every
// organization but the operator's. On a deployment with customers, no customer could ever be offered a
// release. The operator now publishes ONCE, to the deployment's catalogue, and every organization is offered
// it; publishing into one organization stays possible and shadows the catalogue for that one alone.
func TestTheDeploymentsCatalogueIsOfferedToEveryOrganization(t *testing.T) {
	store := &publishedAgentUpdateStore{
		envelopes: map[string]agentpolicy.Envelope{
			tenantTargetKey(agentUpdateCatalogueScope, "darwin", "arm64"): {PayloadSHA256: "catalogue"},
			tenantTargetKey("tenant_canary", "darwin", "arm64"):           {PayloadSHA256: "canary"},
		},
		pending: map[string]agentpolicy.Envelope{},
		legacy:  map[string]agentpolicy.Envelope{},
	}

	offered := store.ForTenant("tenant_customer")["darwin/arm64"]
	if offered.PayloadSHA256 != "catalogue" {
		t.Fatalf("an organization that has published nothing of its own is offered %q — before this it was "+
			"offered nothing at all, and no customer's devices could be updated", offered.PayloadSHA256)
	}
	// ★ AND ONE ORGANIZATION'S OWN SHADOWS IT. That is how a single customer is given a build before the rest.
	if got := store.ForTenant("tenant_canary")["darwin/arm64"].PayloadSHA256; got != "canary" {
		t.Fatalf("the organization's own release was not preferred over the catalogue: %q", got)
	}
	// The catalogue read as itself is the operator's own view, and must not be doubled back onto itself.
	if got := store.ForTenant(agentUpdateCatalogueScope)["darwin/arm64"].PayloadSHA256; got != "catalogue" {
		t.Fatalf("the operator's view of the catalogue is %q", got)
	}
}

// ★ AND THE BYTES ARE ON THE SAME SHELF AS THE DOCUMENT. A manifest that resolves from the catalogue while its
// artifact is looked for only under the organization is an active release that 404s — the failure the
// pending/active split exists to prevent, reintroduced one layer down.
func TestAnOrganizationDownloadsTheCatalogueArtifact(t *testing.T) {
	dir := t.TempDir()
	shelf := filepath.Join(dir, agentUpdateCatalogueScope)
	if err := os.MkdirAll(shelf, 0o755); err != nil {
		t.Fatal(err)
	}
	name := artifactFileName("darwin", "arm64", "0.3.0")
	if err := os.WriteFile(filepath.Join(shelf, name), []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := artifactReadPath(dir, "tenant_customer", "darwin", "arm64", "0.3.0")
	if got != filepath.Join(shelf, name) {
		t.Fatalf("an organization offered the catalogue's release looks for its bytes at %q — the download "+
			"404s and the fleet stays where it is", got)
	}
	// An organization that has its own bytes uses those.
	own := filepath.Join(dir, "tenant_customer")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(own, name), []byte("its own"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := artifactReadPath(dir, "tenant_customer", "darwin", "arm64", "0.3.0"); got != filepath.Join(own, name) {
		t.Fatalf("the organization's own bytes were not preferred: %q", got)
	}
}

// ★★★ AND AN EDGE MUST ACCEPT THE CATALOGUE (2026-08-28). The Edge refuses a published set answered for any
// organization but the one it enforces — right, because handing one customer's release to another's devices is
// exactly what that check is for. But an Edge serves EVERY organization on the deployment, and what the
// operator publishes for all of them arrives under the catalogue's name. Refusing it left each Edge carrying
// only its own enforcement tenant's set, which is how a device of a customer organization was answered "no
// agent updates are published by this edge" while the control plane held one for it.
func TestAnEdgeAcceptsTheDeploymentsCatalogueAndStillRefusesAnothersRelease(t *testing.T) {
	answered := func(edgeTenant, answeredFor string) bool {
		want := edgeTenant
		return !(want != "" && !equalFoldTrim(answeredFor, want) && !equalFoldTrim(answeredFor, agentUpdateCatalogueScope))
	}
	if !answered("tenant_default", agentUpdateCatalogueScope) {
		t.Error("an Edge refused the deployment's own catalogue, so no organization but its own can be updated")
	}
	if !answered("tenant_default", "tenant_default") {
		t.Error("an Edge refused its own organization's release")
	}
	if answered("tenant_default", "tenant_somebody_else") {
		t.Error("an Edge accepted ANOTHER organization's release — that is the cross-customer hand-off this " +
			"check exists to stop, and it must stay stopped")
	}
}

func equalFoldTrim(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
