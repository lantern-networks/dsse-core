//go:build windows

package main

import (
	"crypto"
	"log"
)

// newDeviceKey generates the device key in the TPM when one is usable, and falls back to a file key otherwise —
// LOUDLY, never silently. The generation itself is the honest test: createTPMKey only succeeds if the chip
// actually produced a non-exportable key, so a machine that merely advertises the provider but has no working
// TPM lands on the file path and says so.
func newDeviceKey(deviceID string) (deviceKeyMaterial, error) {
	container := deviceKeyContainerName(deviceID)
	signer, err := createTPMKey(container)
	if err == nil {
		return deviceKeyMaterial{signer: signer, container: container, hardware: true}, nil
	}
	log.Printf("device key: TPM key generation failed (%v) — falling back to a FILE key (copyable). "+
		"This machine has no usable TPM; the device key is NOT hardware-bound", err)
	return newFileDeviceKey()
}

// reopenDeviceKeySigner reconstructs the signer a renewal pointer names by its TPM container, without any key
// material touching disk.
func reopenDeviceKeySigner(container string) (crypto.Signer, error) {
	s, err := openTPMKey(container)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// removeDeviceKeyContainer deletes a TPM container — for rollback of a candidate that failed its probe, and for
// the superseded key after a renewal commits, so failed and old keys do not pile up in the chip.
func removeDeviceKeyContainer(container string) {
	if container == "" {
		return
	}
	if err := deleteTPMKey(container); err != nil {
		log.Printf("device key: could not delete superseded TPM container %q: %v", container, err)
	}
}
