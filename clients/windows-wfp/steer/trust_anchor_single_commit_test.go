package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/durablefile"
)

func TestTrustBundleAdoptionCommitsAnchorsAndPointerTogether(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "single-commit-ca")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		TenantID: "tenant-a", Serial: 1, TransportCAPEM: string(ca.pem),
	}, "", ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, adoptedPointerFile))
	if err != nil {
		t.Fatal(err)
	}
	var pointer map[string]any
	if err := json.Unmarshal(raw, &pointer); err != nil {
		t.Fatal(err)
	}
	if pointer["transport_ca_pem"] != string(ca.pem) {
		t.Fatal("committed pointer must contain the signed CA set")
	}
	// A legacy split-file artifact is not needed for new adoptions: the serial,
	// metadata and CA set must survive in the same durable snapshot.
	if err := os.Remove(filepath.Join(dir, adoptedAnchorsFile)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	_, anchors, serial, ok := adoptedTrustAnchors(dir)
	if !ok || serial != 1 || len(anchors) != 1 || !anchors[0].Equal(ca.cert) {
		t.Fatal("restart did not load the CA from its committed pointer")
	}
}

func TestVisibleButUnflushedTrustRecordUsesMatchingLiveCAAndReportsUncertainty(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "working-ca")
	newCA := newTestCA(t, "visible-ca")
	tc := &transportConfig{enabled: true, liveTrust: &atomic.Pointer[trustMaterial]{}}
	tc.setTrustAnchors(oldCA.pem, 1)
	originalWrite, originalSync := adoptedPointerDurableWrite, adoptedPointerSyncDir
	t.Cleanup(func() { adoptedPointerDurableWrite, adoptedPointerSyncDir = originalWrite, originalSync })
	adoptedPointerDurableWrite = func(path string, data []byte, _ os.FileMode) error {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		return durablefile.ErrReplacedNotFlushed
	}
	adoptedPointerSyncDir = func(string) error { return errors.New("injected directory flush failure") }
	out, ok := adoptVerifiedBundle(tc, trustRecoveryConfig{stateDir: dir, tenantID: "tenant-a"},
		agentpolicy.TrustBundlePayload{TenantID: "tenant-a", Serial: 2, TransportCAPEM: string(newCA.pem)},
		time.Second)
	if ok || out.code != "adopted_unconfirmed" || !strings.Contains(out.detail, "durability is unconfirmed") {
		t.Fatalf("post-rename uncertainty was reported as success or lost: code=%q ok=%v", out.code, ok)
	}
	anchors := tc.currentTrustAnchors()
	if len(anchors) != 1 || !anchors[0].Equal(newCA.cert) || tc.currentTrustSerial() != 2 {
		t.Fatal("visible serial 2 snapshot and live CA must agree")
	}
	if got := lastAcceptedTrustSerial(dir); got != 2 {
		t.Fatalf("visible replay floor=%d, want 2", got)
	}
}

func TestUnconfirmedTrustRecordWithoutExactReadbackKeepsOldLiveCA(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "working-ca")
	newCA := newTestCA(t, "unpublished-ca")
	tc := &transportConfig{enabled: true, liveTrust: &atomic.Pointer[trustMaterial]{}}
	tc.setTrustAnchors(oldCA.pem, 1)
	originalWrite, originalSync := adoptedPointerDurableWrite, adoptedPointerSyncDir
	t.Cleanup(func() { adoptedPointerDurableWrite, adoptedPointerSyncDir = originalWrite, originalSync })
	adoptedPointerDurableWrite = func(string, []byte, os.FileMode) error {
		return durablefile.ErrReplacedNotFlushed
	}
	adoptedPointerSyncDir = func(string) error { t.Fatal("must not sync an absent snapshot"); return nil }
	out, ok := adoptVerifiedBundle(tc, trustRecoveryConfig{stateDir: dir, tenantID: "tenant-a"},
		agentpolicy.TrustBundlePayload{TenantID: "tenant-a", Serial: 2, TransportCAPEM: string(newCA.pem)},
		time.Second)
	if ok || out.code != "unrecovered" {
		t.Fatalf("absent commit appeared adopted: code=%q ok=%v", out.code, ok)
	}
	anchors := tc.currentTrustAnchors()
	if len(anchors) != 1 || !anchors[0].Equal(oldCA.cert) || tc.currentTrustSerial() != 1 {
		t.Fatal("unpublished snapshot changed the working CA")
	}
}

func TestHealthyTrustRecoveryDoesNotCallVisibleUnflushedAdoptionConfirmed(t *testing.T) {
	ca := newTestCA(t, "serving-ca")
	listener := startTransportListener(t, leafUnder(t, ca))
	tc := testTransportConfig(t, listener.Addr().String(), ca)
	signer := newTestSigner(t)
	bundle := startBundleServer(t, signedBundle(t, signer, 2, ca.pem, ""), nil)
	originalWrite, originalSync := adoptedPointerDurableWrite, adoptedPointerSyncDir
	t.Cleanup(func() { adoptedPointerDurableWrite, adoptedPointerSyncDir = originalWrite, originalSync })
	adoptedPointerDurableWrite = func(path string, data []byte, _ os.FileMode) error {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		return durablefile.ErrReplacedNotFlushed
	}
	adoptedPointerSyncDir = func(string) error { return errors.New("injected directory flush failure") }
	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: t.TempDir(), pinHex: signer.PublicKeyHex(), bundleURL: bundle.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "adopted_unconfirmed" || tc.currentTrustSerial() != 2 {
		t.Fatalf("healthy branch hid visible adoption uncertainty: code=%q serial=%d", out.code, tc.currentTrustSerial())
	}
}

func TestTrustBundleReAdoptionPreservesLegacyPairUntilPointerCommit(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "legacy-ca")
	newCA := newTestCA(t, "replacement-ca")
	sum := sha256.Sum256(oldCA.cert.Raw)
	oldPointer, err := json.Marshal(adoptedTrustPointer{
		Serial: 1, TenantID: "tenant-a", Fingerprints: []string{hex.EncodeToString(sum[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), oldPointer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adoptedAnchorsFile), oldCA.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		TenantID: "tenant-a", Serial: 2, TransportCAPEM: string(newCA.pem),
	}, "", ""); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(filepath.Join(dir, adoptedAnchorsFile))
	if err != nil || string(legacy) != string(oldCA.pem) {
		t.Fatal("re-adoption changed the legacy CA before its new pointer committed")
	}
	_, anchors, serial, ok := adoptedTrustAnchors(dir)
	if !ok || serial != 2 || len(anchors) != 1 || !anchors[0].Equal(newCA.cert) {
		t.Fatal("new committed snapshot did not replace the legacy adoption")
	}
}

func TestEmbeddedAdoptedAnchorsRejectFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "old-ca")
	wrongCA := newTestCA(t, "wrong-ca")
	sum := sha256.Sum256(oldCA.cert.Raw)
	pointer, err := json.Marshal(adoptedTrustPointer{
		Serial: 2, TransportCAPEM: string(wrongCA.pem), Fingerprints: []string{hex.EncodeToString(sum[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), pointer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adoptedAnchorsFile), oldCA.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := adoptedTrustAnchors(dir); ok {
		t.Fatal("a corrupt embedded CA must not fall back to a stale legacy file")
	}
}

func TestFailedTrustBundleCommitKeepsCurrentLiveAnchors(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "working-ca")
	newCA := newTestCA(t, "candidate-ca")
	tc := &transportConfig{enabled: true, liveTrust: &atomic.Pointer[trustMaterial]{}}
	tc.setTrustAnchors(oldCA.pem, 1)
	if err := os.Mkdir(filepath.Join(dir, adoptedPointerFile), 0o700); err != nil {
		t.Fatal(err)
	}
	out, ok := adoptVerifiedBundle(tc, trustRecoveryConfig{stateDir: dir, tenantID: "tenant-a"},
		agentpolicy.TrustBundlePayload{TenantID: "tenant-a", Serial: 2, TransportCAPEM: string(newCA.pem)},
		time.Second)
	if ok || out.code != "unrecovered" {
		t.Fatalf("failed commit appeared adopted: code=%q ok=%v", out.code, ok)
	}
	anchors := tc.currentTrustAnchors()
	if len(anchors) != 1 || !anchors[0].Equal(oldCA.cert) || tc.currentTrustSerial() != 1 {
		t.Fatal("failed commit replaced the working live CA set")
	}
}

func TestTrustBundlePointerCommitFailureDoesNotPublishAnOrphanCAFile(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "failed-commit-ca")
	if err := os.Mkdir(filepath.Join(dir, adoptedPointerFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		TenantID: "tenant-a", Serial: 1, TransportCAPEM: string(ca.pem),
	}, "", ""); err == nil {
		t.Fatal("pointer commit should fail when its destination is a directory")
	}
	if _, err := os.Stat(filepath.Join(dir, adoptedAnchorsFile)); !os.IsNotExist(err) {
		t.Fatal("failed pointer commit must not publish a separate new CA file")
	}
}

func TestTrustBundleAdoptionDoesNotReuseAStaleFixedTempName(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "unique-temp-ca")
	stale := filepath.Join(dir, adoptedPointerFile+".tmp")
	if err := os.WriteFile(stale, []byte("unrelated data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		TenantID: "tenant-a", Serial: 1, TransportCAPEM: string(ca.pem),
	}, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(stale)
	if err != nil || string(got) != "unrelated data" {
		t.Fatal("an unrelated fixed-temp artifact was consumed by trust adoption")
	}
}
