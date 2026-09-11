//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCAPEM is a self-signed CA, because the selection parses what it reads and a placeholder string would
// make the test pass for the wrong reason.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test transport CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ★ THE SELECTION HAS TO BE ABLE TO FIND THE ANCHORS ON THE ONLY KIND OF BOX THAT ENROLS (win-dev-1,
// 2026-08-12). transportTrustAnchors is right about WHAT to trust — adopted REPLACES provisioned, never a
// union, and the device-issuing CA is never a substitute — and it is keyed on --transport-pinned-ca, which the
// MSI's service line does not pass. So an enrolled box resolved to no anchor at all and could not complete one
// (T) handshake, twice in a row for two different reasons.
//
// These pin the PATH, because a lookup keyed on a flag nobody passes cannot fail visibly: it just answers
// nothing, and the caller's fallback then looks like the whole story.

func TestAConfigStoreBoxResolvesItsProvisionedAnchor(t *testing.T) {
	state := t.TempDir()
	t.Setenv("ProgramData", state)

	// No flag, which is exactly what `--service-run --config-store` passes.
	got := transportPinPath("")

	want := filepath.Join(state, "DSSE", provisionedTransportCAFile)
	if got != want {
		t.Fatalf("transportPinPath(\"\") = %q, want %q — an enrolled box with no flag resolves to no anchor and "+
			"cannot verify the Edge", got, want)
	}
}

// An explicit flag still wins: a lab or hand-run agent names its own anchor and must not be redirected to the
// installed location.
func TestAnExplicitPinStillWins(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if got := transportPinPath(`C:\lab\my-ca.pem`); got != `C:\lab\my-ca.pem` {
		t.Fatalf("transportPinPath = %q, want the operator's own path", got)
	}
}

// And the whole selection works through it: a provisioned anchor at the well-known name is read, with the
// adopted lookup keyed on the same directory.
func TestTheSelectionReadsTheProvisionedAnchorAtThatPath(t *testing.T) {
	state := t.TempDir()
	t.Setenv("ProgramData", state)
	dsse := filepath.Join(state, "DSSE")
	if err := os.MkdirAll(dsse, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dsse, provisionedTransportCAFile), testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}

	pool, pinned, serial, source, err := transportTrustAnchors(transportPinPath(""), nil)
	if err != nil {
		t.Fatalf("the selection could not use the provisioned anchor a config-store box actually has: %v", err)
	}
	if pool == nil || len(pinned) == 0 {
		t.Fatalf("no anchors were selected (pinned=%d) — this is the empty pool that fails every handshake", len(pinned))
	}
	if serial != 0 {
		t.Fatalf("serial = %d with nothing adopted, want 0", serial)
	}
	if source == "" {
		t.Fatal("the source was not named; the operator's next question is which file answered")
	}
}

// ★ THE TWO CHANGES HAVE TO COMPOSE, AND THIS IS THE SHAPE THAT PROVES IT (2026-08-12, nineteenth). The
// eighteenth review made the adopted store be consulted FIRST so a retired pin cannot take a rotated device
// off the network; transportPinPath supplies the path an installed box never passes. Neither is enough alone
// for the case a real fleet reaches: a config-store device, no flag, **no provisioned file at all** because
// the rotation retired it, and a valid adopted bundle sitting beside its enrolment.
//
// Without the path there is no directory to look in; without the ordering the missing file is an error before
// the bundle is read. Both, and the box verifies the Edge with what it actually adopted.
func TestARotatedConfigStoreBoxUsesItsAdoptedBundleWithNoPinFile(t *testing.T) {
	state := t.TempDir()
	t.Setenv("ProgramData", state)
	dsse := filepath.Join(state, "DSSE")
	if err := os.MkdirAll(dsse, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := installTrustBundle(dsse, agentpolicy.TrustBundlePayload{
		Serial: 7, TransportCAPEM: string(testCAPEM(t))}, "", ""); err != nil {
		t.Fatal(err)
	}
	// No transport_ca.pem is written: this device rotated past the anchor it was born with.

	pool, pinned, serial, source, err := transportTrustAnchors(transportPinPath(""), nil)

	if err != nil {
		t.Fatalf("a rotated config-store box could not assemble an anchor set (%v) — it holds an adopted bundle "+
			"at serial 7 and would be on an empty pool, unable to complete one handshake", err)
	}
	if pool == nil || len(pinned) != 1 {
		t.Fatalf("the adopted anchors were not selected (%d)", len(pinned))
	}
	if serial != 7 {
		t.Fatalf("serial %d — without it a restart reports 0 and nothing re-adopts", serial)
	}
	if source == "" {
		t.Fatal("the source was not named")
	}
}

// The anchors live BESIDE the enrolled material, not inside it: they outlive any one enrolment, and a device
// that re-enrols must not lose what it verifies the Edge with.
func TestTheAnchorIsBesideTheEnrolledMaterialNotInsideIt(t *testing.T) {
	state := t.TempDir()
	t.Setenv("ProgramData", state)
	if got := filepath.Dir(transportPinPath("")); got == defaultEnrollDir() {
		t.Fatalf("the anchor is inside the enrolment directory (%q); a re-enrolment would take it with it", got)
	}
}
