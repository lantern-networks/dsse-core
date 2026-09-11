//go:build !windows

package main

import (
	"crypto"
	"fmt"
)

// On every non-Windows build the device key stays in a file. TPM binding is the Windows slice (Secure Enclave
// on macOS is a separate handoff, gated on Apple provisioning), so these stubs keep the package building and
// its portable renewal/enrolment logic unit-testable on Linux CI.

func newDeviceKey(string) (deviceKeyMaterial, error) { return newFileDeviceKey() }

func reopenDeviceKeySigner(string) (crypto.Signer, error) {
	return nil, fmt.Errorf("TPM key containers are not supported on this platform")
}

func removeDeviceKeyContainer(string) {}
