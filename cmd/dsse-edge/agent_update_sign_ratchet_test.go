package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ THE ATTACK THIS EXISTS FOR (2026-08-13). Device-side publisher verification refuses bytes this publisher
// did not build. It cannot refuse an OLD build that this publisher genuinely did build — those really are our
// bytes, correctly signed and notarized. So the highest-value thing a compromised control plane can still ask
// the HSM for is a signature over a release whose weaknesses are public.
func TestTheControlPlaneWillNotSignAVersionOlderThanOneItAlreadySigned(t *testing.T) {
	dir := t.TempDir()
	r := newAgentUpdateSignRatchet(dir)

	if err := r.Check("tenant_a", "darwin", "arm64", "0.2.9"); err != nil {
		t.Fatalf("the first release for a target must be signable: %v", err)
	}
	if err := r.Record("tenant_a", "darwin", "arm64", "0.2.9"); err != nil {
		t.Fatal(err)
	}

	err := r.Check("tenant_a", "darwin", "arm64", "0.2.4")
	if err == nil {
		t.Fatal("a downgrade was accepted for signing")
	}
	if !strings.Contains(err.Error(), "Roll back instead") {
		t.Fatalf("the refusal must point at the path that still works: %v", err)
	}

	// ★ EQUAL IS ALLOWED, and this is the case the design sketch got wrong. A manifest EXPIRES, so re-signing
	// the same version is routine — a strict "newer only" rule makes every release permanently unpublishable a
	// few weeks after it ships, and the operator's only way out is to invent a version number for a build
	// nobody changed. Re-signing the same version enables no downgrade: it is the same code.
	if err := r.Check("tenant_a", "darwin", "arm64", "0.2.9"); err != nil {
		t.Fatalf("re-signing the same version (expiry renewal) was refused: %v", err)
	}
	if err := r.Check("tenant_a", "darwin", "arm64", "0.3.0"); err != nil {
		t.Fatalf("a newer version was refused: %v", err)
	}

	// The floor is per target and per tenant: one tenant's release history must not restrict another's, and
	// darwin's must not restrict windows'.
	if err := r.Check("tenant_a", "windows", "amd64", "0.1.0"); err != nil {
		t.Fatalf("another target was constrained by darwin's floor: %v", err)
	}
	if err := r.Check("tenant_b", "darwin", "arm64", "0.1.0"); err != nil {
		t.Fatalf("another tenant was constrained by tenant_a's floor: %v", err)
	}
}

// ★ A FLOOR THAT DOES NOT SURVIVE A RESTART IS NOT A FLOOR, and a restart is exactly what an attacker who
// wanted the downgrade would arrange.
func TestTheSigningFloorSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first := newAgentUpdateSignRatchet(dir)
	if err := first.Record("tenant_a", "darwin", "arm64", "0.2.9"); err != nil {
		t.Fatal(err)
	}

	second := newAgentUpdateSignRatchet(dir)
	if err := second.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := second.Check("tenant_a", "darwin", "arm64", "0.2.4"); err == nil {
		t.Fatal("the floor was forgotten across a restart, so the downgrade the previous process refused is now signable")
	}
}

// ★ A RECORD THAT LOWERS THE FLOOR WOULD UNDO THE WHOLE THING. Publishing an older version through the PUT
// door (an envelope signed elsewhere) also records — and must not walk the ratchet backwards.
func TestRecordingAnOlderVersionDoesNotLowerTheFloor(t *testing.T) {
	dir := t.TempDir()
	r := newAgentUpdateSignRatchet(dir)
	if err := r.Record("tenant_a", "darwin", "arm64", "0.2.9"); err != nil {
		t.Fatal(err)
	}
	if err := r.Record("tenant_a", "darwin", "arm64", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := r.Check("tenant_a", "darwin", "arm64", "0.2.0"); err == nil {
		t.Fatal("the floor was lowered by publishing an old release, which is exactly the sequence an attacker would use")
	}
}

// ★ A GUARD THAT CANNOT RUN MUST NOT PASS. A corrupted or hand-edited floor file leaves a value that cannot be
// compared, and the tempting reading — "unparseable, so no constraint" — removes the control at the one moment
// its file has been tampered with.
func TestAnUncomparableFloorRefusesRatherThanWavingItThrough(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent_update_sign_floor.json"),
		[]byte(`{"tenant_a|darwin/arm64":"not-a-version"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newAgentUpdateSignRatchet(dir)
	if err := r.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := r.Check("tenant_a", "darwin", "arm64", "9.9.9"); err == nil {
		t.Fatal("an uncomparable floor allowed signing; the downgrade guard silently stopped existing")
	}
}

// A floor file that is not JSON at all must stop the process rather than start with an empty floor — the
// version an empty floor permits is the old one.
func TestAnUnreadableFloorIsAnErrorAndNotACleanStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent_update_sign_floor.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newAgentUpdateSignRatchet(dir).Load(); err == nil {
		t.Fatal("a corrupted floor loaded as an empty one")
	}
	// A missing file IS a clean start: that is a control plane that has never signed anything.
	if err := newAgentUpdateSignRatchet(t.TempDir()).Load(); err != nil {
		t.Fatalf("a first run must not be an error: %v", err)
	}
}

// ★★ ONE TENANT MUST NOT READ ANOTHER'S RELEASE HISTORY (2026-08-13, thirtieth review #15). The floor map is
// keyed "<tenant>|<platform>/<arch>", and the route returned it whole — so a tenant-scoped administrator could
// read which targets another tenant ships and the highest version it has signed, from a screen about their own
// fleet. Every other route in this lane scopes by the caller's tenant; this one was written last and did not.
func TestTheSigningFloorIsScopedToTheCallersTenant(t *testing.T) {
	r := newAgentUpdateSignRatchet(t.TempDir())
	if err := r.Record("tenant_a", "darwin", "arm64", "0.9.0"); err != nil {
		t.Fatal(err)
	}
	if err := r.Record("tenant_b", "windows", "amd64", "0.4.2"); err != nil {
		t.Fatal(err)
	}

	a := r.FloorsForTenant("tenant_a")
	if len(a) != 1 || a["darwin/arm64"] != "0.9.0" {
		t.Fatalf("tenant_a should see exactly its own floor, saw %v", a)
	}
	for key := range a {
		if strings.Contains(key, "tenant_") {
			t.Fatalf("the key %q names a tenant — the same disclosure in a smaller font", key)
		}
	}
	if b := r.FloorsForTenant("tenant_b"); len(b) != 1 || b["windows/amd64"] != "0.4.2" {
		t.Fatalf("tenant_b lost its own floor: %v", b)
	}
	if n := len(r.FloorsForTenant("tenant_never_published")); n != 0 {
		t.Fatalf("a tenant that has published nothing saw %d floors", n)
	}
}
