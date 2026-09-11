//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// machine_reference_windows.go — which MACHINE this is, as opposed to what it is called.
//
// ★★★ THE NAME ALONE CANNOT ANSWER "IS THIS THE SAME BOX?" (2026-08-25). A device enrols under the name its
// own operating system gives it, which is right — but two machines called "laptop" are ordinary, and a second
// enrolment of one name then has three causes that look identical to the deployment: the same machine coming
// back, a namesake that must be renamed, and a machine that WAS renamed and is about to become a second
// device. The refusal had to name them all and let an operator guess, with the one-time token already spent.
//
// ★ IT IS EVIDENCE, NEVER A CREDENTIAL. This agent reports it, so anything can claim any value; it cannot
// grant an enrolment or widen one. What authenticates this device is the certificate it is issued.
//
// ★ AND IT IS NOT A HARDWARE SERIAL. MachineGuid survives reinstalling the agent, reinstalling this product,
// and renaming the computer. It does NOT survive reinstalling Windows or cloning a disk image without
// sysprep — which is correct for what it is used for: a rebuilt machine SHOULD look like a different one, and
// an administrator permitting re-enrolment is the way back.
func machineReference() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		// Absent is a supported answer: the deployment then behaves exactly as it did before this existed.
		// Refusing to enrol because a registry value could not be read would trade a distinction for a device.
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return normalizeMachineReference(v)
}

// normalizeMachineReference trims and lower-cases, and nothing else — the deployment treats the value as
// opaque, and rewriting it further would make two agents reporting one machine disagree.
func normalizeMachineReference(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
