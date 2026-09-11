package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// device_key.go — the platform-neutral seam for where a device private key lives. The renewal and enrolment
// paths ask for a key without knowing whether it is generated in the TPM or in a file; the Windows build binds
// it to the TPM (device_key_windows.go), and every other build keeps the file key (device_key_other.go).
//
// This is what makes "bind the key to the TPM" a change of ONE thing — where the key is generated — rather than
// a rewrite of the identity lifecycle. A device that renews picks up a TPM key on its next renewal with no
// server change and no fleet-wide switch; a machine with no usable TPM keeps working on a file key and SAYS SO.

// deviceKeyMaterial is a freshly generated device key plus how to persist and later reopen it. Exactly one of
// keyPEM (a file key to write) or container (a TPM key to name) is set.
type deviceKeyMaterial struct {
	signer    crypto.Signer // what CSRs and the (T) handshake sign with; a *ecdsa.PrivateKey or a TPM signer
	keyPEM    []byte        // FILE key material to persist; nil for a TPM key
	container string        // TPM container name; "" for a file key
	hardware  bool          // true when the key is TPM-bound (non-exportable)
}

// storageLabel is the exact line the handoff mandates for the startup log and status: it must never be silent
// about running on a copyable file key while believing it is in hardware.
func (m deviceKeyMaterial) storageLabel() string {
	if m.hardware {
		return "TPM (Microsoft Platform Crypto Provider, container=" + m.container + ")"
	}
	return "FILE — this machine has no usable TPM; the device key is copyable"
}

// deviceKeyContainerName ties a TPM container to the identity it serves, with a random suffix so each renewal
// gets its own container (the old one is deleted only after the new one is proven). Uniqueness matters more than
// the exact shape; it just has to be stable within one key's life and distinct across keys.
func deviceKeyContainerName(deviceID string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	id := deviceID
	if id == "" {
		id = "device"
	}
	return fmt.Sprintf("dsse-device-%s-%s", id, hex.EncodeToString(b[:]))
}

// newFileDeviceKey generates the ordinary in-file ECDSA P-256 key. It is the fallback on Windows without a
// usable TPM and the only path on every other platform. A FRESH key every time — renewal never re-certifies an
// existing one, so a key that leaked once is not blessed again.
func newFileDeviceKey() (deviceKeyMaterial, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return deviceKeyMaterial{}, fmt.Errorf("generate device key: %w", err)
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return deviceKeyMaterial{}, err
	}
	return deviceKeyMaterial{signer: key, keyPEM: keyPEM, hardware: false}, nil
}

// expectedECDSAPublicKey extracts the *ecdsa.PublicKey a signer commits to, so validateIssued can confirm the
// Edge signed a certificate for THIS key regardless of whether it lives in a file or the TPM.
func expectedECDSAPublicKey(signer crypto.Signer) (*ecdsa.PublicKey, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device key is not ECDSA (%T)", signer.Public())
	}
	return pub, nil
}
