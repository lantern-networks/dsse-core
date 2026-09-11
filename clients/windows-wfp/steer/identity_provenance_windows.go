//go:build windows

package main

// identity_provenance_windows.go -- saying WHICH CONTEXT opened the device key.
//
// ★★★ THREE DIAGNOSES IN ONE DAY TURNED ON THIS AND NOTHING SAID IT (2026-08-30).
//
// The device key is DPAPI-wrapped at the context that enrolled, and "SYSTEM" is not one context:
//
//   - a read-only diagnostic (--mode bypass-observe) enrolled, wrapping the key in an operator's session, so
//     the service could never open it;
//   - an identity minted by a SYSTEM SCHEDULED TASK could not be opened by the LocalSystem SERVICE, though
//     both are S-1-5-18 -- DPAPI user scope depends on the profile, and a task with LogonType ServiceAccount
//     and a service do not share it;
//   - and the shipped path -- seed as SYSTEM, let the SERVICE enrol -- worked, because there the minting
//     context and the using context are the same process by construction.
//
// Every one of those was diagnosed by moving the identity around until something worked. The agent said
// "loaded enrolled device identity (device=... tenant=...)" in all three cases and stopped there. What it
// never said is the only thing that separated them.
//
// ★ IT REPORTS WHAT IT CAN PROVE. "Service" is known because this process was started by the SCM
// (--service-run); SYSTEM-but-not-the-service is a real and different answer, and it is the one that looks
// identical to the service in every other log line. A named user is reported by name, because a key wrapped
// there is the one an operator has to be told about.

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// identityContext names the security context this process runs in, in the terms that decide whether a
// DPAPI-wrapped device key will open.
func identityContext(isServiceRun bool) string {
	if isServiceRun {
		return "service (LocalSystem, started by the SCM)"
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "unknown (this process could not read its own token)"
	}
	sid := u.User.Sid
	name, domain, _, nerr := sid.LookupAccount("")
	who := sid.String()
	if nerr == nil {
		if domain != "" {
			who = domain + `\` + name
		} else {
			who = name
		}
	}
	// S-1-5-18 is LocalSystem. Reached WITHOUT --service-run it is a scheduled task, a psexec -s, or an
	// interactive SYSTEM shell -- and a key wrapped in one of those is not openable by the service, which is
	// the failure this line exists to make visible before somebody spends an approval on it.
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		return "SYSTEM but NOT the service (" + who + ") — a key wrapped here is not openable by DsseSteer"
	}
	return "user " + who + " — a key wrapped here is not openable by DsseSteer"
}

// reportIdentityProvenance prints the identity in force AND the context that opened it.
func reportIdentityProvenance(deviceID, tenant string, isServiceRun bool) {
	fmt.Printf("steer: loaded enrolled device identity (device=%q tenant=%q) for the (T) transport — "+
		"unwrapped_in=%s\n", deviceID, tenant, identityContext(isServiceRun))
}
