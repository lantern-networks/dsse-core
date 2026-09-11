package main

import (
	"crypto/x509"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ★★★ THE ARCHITECTURE NAMES THREE TIERS AND THIS INSTALLER MINTED TWO. A deployment without an interception
// authority inspects nothing, and said so nowhere: the generated start script did not mention interception,
// and the organization checklist reported done 4/13, blocking [].
func TestTheDeploymentMintsAllThreeTiers(t *testing.T) {
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	for _, tier := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"transport", a.TransCA},
		{"device-identity", a.DeviceCA},
		{"interception", a.InterceptCA},
	} {
		if tier.cert == nil {
			t.Fatalf("the %s tier was not minted", tier.name)
		}
		if !tier.cert.IsCA {
			t.Fatalf("the %s tier is not a CA", tier.name)
		}
		if err := tier.cert.CheckSignatureFrom(a.RootCert); err != nil {
			t.Fatalf("the %s tier does not chain to this deployment's root: %v", tier.name, err)
		}
		// ★ ROOM UNDERNEATH. A per-node short-lived issuing CA sits below a tier, which is how interception is
		// delegated to an Edge without handing it this key. pathlen:0 makes that chain invalid — a mistake
		// this deployment has already made once.
		if tier.cert.MaxPathLen < 1 {
			t.Fatalf("the %s tier leaves no room for a CA underneath (pathlen=%d)", tier.name, tier.cert.MaxPathLen)
		}
	}
}

// The engine reuses root material already on disk and mints its own only when there is none, so the names
// have to be the ones it reads — otherwise every Edge invents a root nobody else has heard of.
func TestTheInterceptionAuthorityIsWrittenWhereTheEdgeReadsIt(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	certPath := filepath.Join(dir, "lantern_dsse_interception_root_ca.pem")
	keyPath := filepath.Join(dir, "lantern_dsse_interception_root_ca.key.pem")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("the interception certificate is not where the Edge looks: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("the interception key is not where the Edge looks: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the key that signs every site certificate this deployment presents is %v", info.Mode().Perm())
	}
}

// ★ A DEPLOYMENT MINTED BEFORE THIS EXISTED MUST SAY SO RATHER THAN START QUIETLY. Its directory has no
// interception authority, and starting an Edge that inspects nothing without a word is how "done 4/13,
// blocking []" happened in the first place.
func TestTheStartScriptSaysWhenThereIsNoInterceptionAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("write launch scripts: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatalf("read start-edge.sh: %v", err)
	}
	script := string(raw)
	if !strings.Contains(script, "lab-tls-interception-hosts") {
		t.Fatal("the start script never enables interception, so the deployment inspects nothing")
	}
	if !strings.Contains(script, "NOTHING WILL BE INSPECTED") {
		t.Fatal("a deployment with no interception authority must say so, not start quietly")
	}
	if !strings.Contains(script, "sni-based-intercept") {
		t.Fatal("a steer-all agent hands over addresses, not names — deciding from the address intercepts the " +
			"wrong things and misses the rest")
	}
	if !strings.Contains(script, "$INTERCEPT") {
		t.Fatal("the flags are assembled and never passed to the Edge")
	}
}

// ★★★ A DEPLOYMENT RUNNING SINCE BEFORE THE TIER EXISTED HAS NO OTHER WAY TO GET IT. Adding one orphans
// nothing — nothing has ever been issued under it — so it is repair, not rotation.
func TestAnExistingDeploymentIsGivenTheTierItNeverHad(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Take it away, the way a deployment generated before 2026-08-26 looks.
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.key.pem"))

	minted, err := mintTheInterceptionTierIfMissing(dir, time.Now(), 10)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if !minted {
		t.Fatal("a deployment with no interception authority must be given one")
	}
	cert, err := readCertificate(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	if err != nil {
		t.Fatalf("read the minted tier: %v", err)
	}
	if err := cert.CheckSignatureFrom(a.RootCert); err != nil {
		t.Fatalf("the added tier must be signed by THIS deployment's root, or it is a second authority "+
			"arriving beside the first: %v", err)
	}

	// ★ IDEMPOTENT. Running repair again must not mint a second one — a deployment that changes the authority
	// signing every site certificate on every repair is worse than one that never had it.
	before, _ := os.ReadFile(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	minted, err = mintTheInterceptionTierIfMissing(dir, time.Now(), 10)
	if err != nil || minted {
		t.Fatalf("repair minted again: minted=%v err=%v", minted, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	if string(before) != string(after) {
		t.Fatal("the interception authority changed on a second repair")
	}
}

// ★ A ROOT KEY THAT IS OFFLINE — where it belongs — must not stop the rest of a repair, and must not be
// silent about what it costs.
func TestAnOfflineRootDoesNotStopTheRepairButIsSaidOutLoud(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.key.pem"))
	// ★ TAKEN OFFLINE — and it now lives under authority/, where no running node is handed it. Removing the
	// old path would leave the key in place and the test would assert nothing.
	_ = os.Remove(authorityPath(dir, "root.key"))

	minted, err := mintTheInterceptionTierIfMissing(dir, time.Now(), 10)
	if err != nil {
		t.Fatalf("an offline root must not fail the repair: %v", err)
	}
	if minted {
		t.Fatal("nothing can be minted without the root key")
	}
}

// ★★★ A TIER IS A DEPLOYMENT FACT, AND MINTING ONE PER DIRECTORY MAKES TWO. Measured within minutes of
// writing the repair: a two-region deployment is repaired by running it in each region's directory, both hold
// the same root key, and both minted — one root, two interception authorities, each region signing under its
// own. The very repair meant to close a gap reproduced the "second deployment wearing different clothes"
// shape this installer refuses everywhere else.
func TestAJoiningRegionCarriesTheTierRatherThanMintingOne(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.key.pem"))

	// This directory stands up a region that holds no state — a joining region.
	if err := writeComposeFileFor(dir, machineShape{holds: regionShapeEdgesOnly, edges: true}); err != nil {
		t.Fatalf("render a joining region: %v", err)
	}
	if shape, known := regionShapeFromCompose(dir); !known || shape.holds == regionShapeStateBearing {
		t.Fatalf("the fixture is not a joining region (known=%v shape=%v)", known, shape)
	}

	minted, err := mintTheInterceptionTierIfMissing(dir, time.Now(), 10)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if minted {
		t.Fatal("a joining region must CARRY the deployment's interception authority, not mint a second one")
	}
	if _, err := os.Stat(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem")); err == nil {
		t.Fatal("a joining region wrote an interception authority of its own")
	}

	// The control: the region that holds the deployment's state does mint one.
	stateDir := t.TempDir()
	if err := writeAuthorities(stateDir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = os.Remove(filepath.Join(stateDir, "lantern_dsse_interception_root_ca.pem"))
	_ = os.Remove(filepath.Join(stateDir, "lantern_dsse_interception_root_ca.key.pem"))
	if err := writeComposeFileFor(stateDir, machineShape{holds: regionShapeStateBearing, edges: true}); err != nil {
		t.Fatalf("render a state-bearing region: %v", err)
	}
	if minted, err := mintTheInterceptionTierIfMissing(stateDir, time.Now(), 10); err != nil || !minted {
		t.Fatalf("the state-bearing region must mint it: minted=%v err=%v", minted, err)
	}
}

// ★★★ A TIER WHOSE KEY TYPE ITS OWN ENGINE CANNOT LOAD IS NOT A TIER. Found by the Edge refusing to start:
// "lab TLS persistent root key is not RSA". Every other authority here is P-256 because its only consumers
// are this deployment's own code; this one's consumer is a browser, and the engine that signs site
// certificates under it holds an RSA key throughout.
func TestTheInterceptionTierIsMaterialTheEdgeCanActuallyLoad(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The Edge's own loader is the judge — not a re-implementation of it here, which is how the first version
	// passed while the Edge refused to start.
	material, reused, err := edgeplane.LoadNetworkExtensionLabTLSPersistentRootMaterial(
		filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"), time.Now)
	if err != nil {
		t.Fatalf("the Edge cannot load what this installer wrote: %v", err)
	}
	if !reused {
		t.Fatal("the Edge did not recognise this as material to reuse — it would mint a root of its own, and " +
			"every node in the fleet would then sign under a different authority")
	}
	if material.Cert == nil || material.Key == nil {
		t.Fatal("the material came back empty")
	}
	if err := material.Cert.CheckSignatureFrom(a.RootCert); err != nil {
		t.Fatalf("what the Edge loaded does not chain to this deployment's root: %v", err)
	}
}

// The same, for a deployment given the tier by repair rather than at mint time.
func TestTheTierAddedByRepairIsAlsoLoadable(t *testing.T) {
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"))
	_ = os.Remove(filepath.Join(dir, "lantern_dsse_interception_root_ca.key.pem"))
	if minted, err := mintTheInterceptionTierIfMissing(dir, time.Now(), 10); err != nil || !minted {
		t.Fatalf("repair: minted=%v err=%v", minted, err)
	}
	if _, reused, err := edgeplane.LoadNetworkExtensionLabTLSPersistentRootMaterial(
		filepath.Join(dir, "lantern_dsse_interception_root_ca.pem"), time.Now); err != nil || !reused {
		t.Fatalf("the Edge cannot load what repair wrote: reused=%v err=%v", reused, err)
	}
}
