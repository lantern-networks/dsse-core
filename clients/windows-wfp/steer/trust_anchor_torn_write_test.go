package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// A crash during a re-adoption writes the new anchors file (first) but not the new pointer (second), leaving the
// NEW anchors beside the OLD pointer/serial. adoptedTrustAnchors must treat that torn pair as unusable and fall
// back to the provisioned anchors, rather than serving new anchors under a stale serial — which would weaken the
// monotonic replay guard that keeps a withdrawn CA from being re-adopted.
func TestAdoptedTrustAnchorsRejectsTornWrite(t *testing.T) {
	dir := t.TempDir()
	caOld := newTestCA(t, "old anchor CA")
	caNew := newTestCA(t, "new anchor CA")
	fp := func(der []byte) string { s := sha256.Sum256(der); return hex.EncodeToString(s[:]) }

	writeAnchors := func(cert *x509.Certificate) {
		if err := os.WriteFile(filepath.Join(dir, adoptedAnchorsFile),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writePtr := func(p adoptedTrustPointer) {
		raw, _ := json.Marshal(p)
		if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Torn: file holds the NEW anchor, pointer still names the OLD fingerprint at its serial.
	writeAnchors(caNew.cert)
	writePtr(adoptedTrustPointer{Serial: 5, Fingerprints: []string{fp(caOld.cert.Raw)}})
	if _, _, _, ok := adoptedTrustAnchors(dir); ok {
		t.Fatal("a torn anchors/pointer pair must be rejected (ok=false), not served under the stale serial")
	}

	// Consistent: the pointer's fingerprint matches the file → adopted, serial reported.
	writePtr(adoptedTrustPointer{Serial: 5, Fingerprints: []string{fp(caNew.cert.Raw)}})
	_, cas, serial, ok := adoptedTrustAnchors(dir)
	if !ok || serial != 5 || len(cas) != 1 {
		t.Fatalf("a consistent pair must be adopted: ok=%v serial=%d cas=%d", ok, serial, len(cas))
	}

	// Backward-compat: a pre-fingerprint pointer (no Fingerprints recorded) is not rejected by this check.
	writePtr(adoptedTrustPointer{Serial: 5})
	if _, _, _, ok := adoptedTrustAnchors(dir); !ok {
		t.Fatal("a pre-fingerprint pointer must still be usable (the integrity check is skipped when Fingerprints is empty)")
	}
}
