//go:build windows

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tpm_key_windows.go — the device private key, generated inside the TPM and never written to a file.
//
// The chain that establishes a device identity had one paper link left: the private key itself. Enrolment mints
// it on the device and renewal replaces it, but until now it lived in a file, and #23 showed a non-root process
// could sign with that file — an ACL cannot close that, only hardware binding can. This puts the key in the TPM
// via CNG's Microsoft Platform Crypto Provider: it is created there, marked non-exportable (the default, which
// we never override), and every signature happens inside the chip. Go only ever holds a handle and a crypto.Signer.
//
// Deliberately NOT here: TPM attestation. Nothing here proves to the Edge that the key is in hardware — that
// needs an AK certificate chain and is a separate slice. This slice makes the key uncopyable; proving remotely
// that it is uncopyable comes later.

var (
	ncrypt                        = windows.NewLazyDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	platformCryptoProvider = "Microsoft Platform Crypto Provider"
	ecdsaP256Algorithm     = "ECDSA_P256"
	eccPublicBlobType      = "ECCPUBLICBLOB"
	eccPrivateBlobType     = "ECCPRIVATEBLOB"

	ncryptMachineKeyFlag   = 0x00000020
	ncryptSilentFlag       = 0x00000040 // never surface a UI prompt — this runs as a service
	ncryptOverwriteKeyFlag = 0x00000080
)

// tpmPrivateKeyExportable reports whether the PRIVATE key can be exported. It must always be false for a PCP
// key; the test asserts that, because an exportable key would make this whole slice pointless. Kept beside the
// NCrypt plumbing rather than in the test so it uses the same call path the real code trusts.
func tpmPrivateKeyExportable(hKey uintptr) bool {
	blobType, _ := windows.UTF16PtrFromString(eccPrivateBlobType)
	var cb uint32
	r, _, _ := procNCryptExportKey.Call(hKey, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag)
	return r == 0 // success here would mean the private key came out — it must not
}

// tpmSigner is a crypto.Signer whose private key lives in the TPM. crypto/tls and x509.CreateCertificateRequest
// accept it as-is, so the rest of the agent does not know or care that signing happens in hardware.
type tpmSigner struct {
	prov      uintptr
	key       uintptr
	pub       *ecdsa.PublicKey
	container string
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

// Sign performs the ECDSA signature INSIDE the TPM. The digest is already hashed by the caller (crypto/tls,
// x509); NCryptSignHash returns the raw r||s, which we re-encode as the ASN.1 DER that Go's TLS/x509 expect.
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ncryptSignECDSA(s.key, digest)
}

// container returns the PCP container name so the pointer can name the key without ever holding key material.
func (s *tpmSigner) containerName() string { return s.container }

// createTPMKey generates a fresh non-exportable ECDSA P-256 key in the TPM under container. It returns an error
// (rather than falling back) so the caller can decide between hardware and a file key and LOG which — a silent
// fallback is the one outcome the handoff forbids.
func createTPMKey(container string) (*tpmSigner, error) {
	prov, err := ncryptOpenPlatformProvider()
	if err != nil {
		return nil, err
	}
	algo, _ := windows.UTF16PtrFromString(ecdsaP256Algorithm)
	name, _ := windows.UTF16PtrFromString(container)
	var hKey uintptr
	// No export policy is set: the default for a PCP key is non-exportable, which is exactly what we want and
	// must never widen. dwLegacyKeySpec=0 (AT_NONE). Machine key store so the SYSTEM service can use it.
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algo)), uintptr(unsafe.Pointer(name)), 0,
		ncryptMachineKeyFlag|ncryptOverwriteKeyFlag)
	if r != 0 {
		procNCryptFreeObject.Call(prov)
		return nil, fmt.Errorf("NCryptCreatePersistedKey: 0x%08x", uint32(r))
	}
	if r, _, _ := procNCryptFinalizeKey.Call(hKey, ncryptSilentFlag); r != 0 {
		procNCryptFreeObject.Call(hKey)
		procNCryptFreeObject.Call(prov)
		return nil, fmt.Errorf("NCryptFinalizeKey: 0x%08x", uint32(r))
	}
	pub, err := ncryptExportPublicECDSA(hKey)
	if err != nil {
		procNCryptFreeObject.Call(hKey)
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	return &tpmSigner{prov: prov, key: hKey, pub: pub, container: container}, nil
}

// openTPMKey reopens an existing TPM key by container name — used at startup to reconstruct the signer the
// renewal pointer names, without any key material ever touching disk.
func openTPMKey(container string) (*tpmSigner, error) {
	prov, err := ncryptOpenPlatformProvider()
	if err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(container)
	var hKey uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag)
	if r != 0 {
		procNCryptFreeObject.Call(prov)
		return nil, fmt.Errorf("NCryptOpenKey %q: 0x%08x", container, uint32(r))
	}
	pub, err := ncryptExportPublicECDSA(hKey)
	if err != nil {
		procNCryptFreeObject.Call(hKey)
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	return &tpmSigner{prov: prov, key: hKey, pub: pub, container: container}, nil
}

// deleteTPMKey removes a container. Called for rollback (a candidate that failed its probe) and for the
// superseded key after a renewal commits — otherwise failed and old keys pile up in the TPM, which is the
// orphan-accumulation problem (#23) in a different store.
func deleteTPMKey(container string) error {
	prov, err := ncryptOpenPlatformProvider()
	if err != nil {
		return err
	}
	defer procNCryptFreeObject.Call(prov)
	name, _ := windows.UTF16PtrFromString(container)
	var hKey uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag)
	if r != 0 {
		return fmt.Errorf("NCryptOpenKey for delete %q: 0x%08x", container, uint32(r))
	}
	// NCryptDeleteKey rejects NCRYPT_SILENT_FLAG on the platform provider (NTE_BAD_FLAGS); it takes 0. Deletion
	// of a machine key needs no UI anyway, so there is nothing to silence.
	if r, _, _ := procNCryptDeleteKey.Call(hKey, 0); r != 0 {
		return fmt.Errorf("NCryptDeleteKey %q: 0x%08x", container, uint32(r))
	}
	return nil
}

// tpmUsable reports whether a real TPM key can be created here, by creating a throwaway key and deleting it.
// Only a create actually exercises the chip — opening the provider succeeds on machines with no usable TPM — and
// this is the honest test the handoff asks for before claiming "TPM" in the log.
func tpmUsable(probeContainer string) bool {
	s, err := createTPMKey(probeContainer)
	if err != nil {
		return false
	}
	s.close()
	_ = deleteTPMKey(probeContainer)
	return true
}

func (s *tpmSigner) close() {
	if s == nil {
		return
	}
	if s.key != 0 {
		procNCryptFreeObject.Call(s.key)
	}
	if s.prov != 0 {
		procNCryptFreeObject.Call(s.prov)
	}
}

func ncryptOpenPlatformProvider() (uintptr, error) {
	name, _ := windows.UTF16PtrFromString(platformCryptoProvider)
	var prov uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(name)), 0)
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider(%q): 0x%08x", platformCryptoProvider, uint32(r))
	}
	return prov, nil
}

// ncryptExportPublicECDSA reads the PUBLIC key (the only thing exportable) as a BCRYPT_ECCKEY_BLOB and rebuilds
// an *ecdsa.PublicKey. The private key has no export policy, so the same call on it fails — which the test
// asserts as the property that matters.
func ncryptExportPublicECDSA(hKey uintptr) (*ecdsa.PublicKey, error) {
	blobType, _ := windows.UTF16PtrFromString(eccPublicBlobType)
	var cb uint32
	r, _, _ := procNCryptExportKey.Call(hKey, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&cb)), 0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey(size): 0x%08x", uint32(r))
	}
	buf := make([]byte, cb)
	r, _, _ = procNCryptExportKey.Call(hKey, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), 0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey: 0x%08x", uint32(r))
	}
	// BCRYPT_ECCKEY_BLOB: ULONG dwMagic; ULONG cbKey; then X[cbKey], Y[cbKey].
	if len(buf) < 8 {
		return nil, fmt.Errorf("ECC public blob too short (%d bytes)", len(buf))
	}
	cbKey := binary.LittleEndian.Uint32(buf[4:8])
	if uint32(len(buf)) < 8+2*cbKey {
		return nil, fmt.Errorf("ECC public blob truncated: have %d, need %d", len(buf), 8+2*cbKey)
	}
	x := new(big.Int).SetBytes(buf[8 : 8+cbKey])
	y := new(big.Int).SetBytes(buf[8+cbKey : 8+2*cbKey])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// ncryptSignECDSA signs a pre-hashed digest in the TPM and returns an ASN.1 DER ECDSA signature. NCryptSignHash
// returns the raw fixed-width r||s; Go's crypto/tls and x509 verifiers expect DER, so the two halves are
// re-encoded as a SEQUENCE of two INTEGERs.
func ncryptSignECDSA(hKey uintptr, digest []byte) ([]byte, error) {
	var cb uint32
	r, _, _ := procNCryptSignHash.Call(hKey, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash(size): 0x%08x", uint32(r))
	}
	raw := make([]byte, cb)
	r, _, _ = procNCryptSignHash.Call(hKey, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&raw[0])), uintptr(cb), uintptr(unsafe.Pointer(&cb)), ncryptSilentFlag)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash: 0x%08x", uint32(r))
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("unexpected raw ECDSA signature length %d", len(raw))
	}
	n := len(raw) / 2
	sig := struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:n]),
		S: new(big.Int).SetBytes(raw[n:]),
	}
	return asn1.Marshal(sig)
}
