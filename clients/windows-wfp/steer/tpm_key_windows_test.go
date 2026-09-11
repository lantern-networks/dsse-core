//go:build windows

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

// These exercise the real TPM via CNG. OFF unless a usable TPM is present — a CI runner or a VM without a vTPM
// would only produce noise. The gate is tpmUsable itself, which creates and deletes a throwaway key.
func requireTPM(t *testing.T) {
	t.Helper()
	if !tpmUsable("dsse-test-probe") {
		t.Skip("no usable TPM (Microsoft Platform Crypto Provider) on this machine")
	}
}

// A TPM key signs, the signature verifies against the exported public key, and the private half CANNOT be
// exported — the whole point. Create and delete are symmetric so the test leaves no container behind.
func TestTPMKeySignsAndIsNonExportable(t *testing.T) {
	requireTPM(t)
	container := "dsse-test-sign-" + randContainerSuffix(t)
	signer, err := createTPMKey(container)
	if err != nil {
		t.Fatalf("createTPMKey: %v", err)
	}
	defer func() {
		signer.close()
		if err := deleteTPMKey(container); err != nil {
			t.Errorf("cleanup deleteTPMKey: %v", err)
		}
	}()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *ecdsa.PublicKey", signer.Public())
	}
	digest := sha256.Sum256([]byte("bind the device key to the TPM"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("the TPM signature did not verify against the exported public key")
	}

	// The private key must not be exportable. NCryptExportKey of a private blob has to fail — if it ever
	// succeeds, the key is copyable and this whole slice is void.
	if exportable := tpmPrivateKeyExportable(signer.key); exportable {
		t.Fatal("the TPM private key was exportable — it must never be")
	}
}

// A reopened container signs for the SAME public key — this is what makes the pointer able to name a key by
// container across restarts without holding any key material.
func TestTPMKeyReopenSameIdentity(t *testing.T) {
	requireTPM(t)
	container := "dsse-test-reopen-" + randContainerSuffix(t)
	created, err := createTPMKey(container)
	if err != nil {
		t.Fatalf("createTPMKey: %v", err)
	}
	createdPub := created.Public().(*ecdsa.PublicKey)
	created.close()
	defer deleteTPMKey(container)

	reopened, err := openTPMKey(container)
	if err != nil {
		t.Fatalf("openTPMKey: %v", err)
	}
	defer reopened.close()
	reopenedPub := reopened.Public().(*ecdsa.PublicKey)
	if createdPub.X.Cmp(reopenedPub.X) != 0 || createdPub.Y.Cmp(reopenedPub.Y) != 0 {
		t.Fatal("reopened container has a different public key")
	}
	// And it can produce a CSR, which is all renewal/enrolment ever ask of it.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "win-dev-test"}}, reopened)
	if err != nil {
		t.Fatalf("CreateCertificateRequest with a TPM signer: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("the TPM-signed CSR did not verify: parse=%v", err)
	}
}

// deleteTPMKey of a name that was never created must error rather than silently "succeed" — the caller relies
// on it to know a rollback actually removed the container.
func TestTPMDeleteMissingErrors(t *testing.T) {
	requireTPM(t)
	if err := deleteTPMKey("dsse-test-does-not-exist-" + randContainerSuffix(t)); err == nil {
		t.Fatal("deleting a nonexistent container reported success")
	}
}

func randContainerSuffix(t *testing.T) string {
	t.Helper()
	// A timestamp is unique enough for a test container and needs no extra imports beyond what the suite uses.
	return time.Now().UTC().Format("150405.000000000")
}
