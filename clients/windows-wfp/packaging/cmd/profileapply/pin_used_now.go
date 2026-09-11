package main

// pin_used_now.go — the third value in the pin story, and the one that had nobody comparing it.
//
// ★★★ MEASURED ON win-dev-1, 2026-09-01, MOVING THIS BOX BETWEEN TWO ORGANIZATIONS. There are three keys
// in play at a provision, not two:
//
//	recorded   %ProgramData%\DSSE\profile_signing_key.txt   what a person reads
//	in force   the DsseSteer service's --config-pin         what the agent verifies the NEXT profile with
//	★ used now the key THIS run verified the profile with   what just decided the install
//
// comparePins compares the first two. Both are written by --pin-file, so after a provision WITH that file
// they always agree and the report is honest. Pass --pin instead (or rely on a baked-in pin) and neither
// record is touched -- so the two still agree, with each other, on the PREVIOUS deployment's key, and the
// line printed at the end of a successful provision reads:
//
//	profileapply: the recorded key and the key in force agree (f53413bfedec3517…)
//
// That sentence is true. It is also printed at the exact moment the device has been provisioned for a new
// organization against a key neither record names, and it reads as reassurance. The device applies this
// profile correctly and then verifies its NEXT one against an authority that no longer issues to it: the
// agent falls back to safe defaults and stops steering, and nothing in this output pointed at why.
//
// ★ IT REPORTS, IT DOES NOT REPAIR. Same rule as comparePins, for the same reason: deciding on its own
// which of three copies is right is how a discrepancy gets papered over instead of looked at. And the fix
// is not something this can do silently anyway -- putting a key in force is exactly the act the operator
// is supposed to perform deliberately, with the file the Console issued.

import "strings"

// usedNowNote reports the key this run verified with against the key that will verify the next one. Empty
// string means there is nothing to say: they match, or one of them is unknown.
//
// Both arguments are public keys and safe to print; usedNow is the value the caller already passed on the
// command line, and inForce is readable by anyone who can list the service's configuration.
func usedNowNote(usedNow string, a pinAgreement) string {
	u := strings.ToLower(strings.TrimSpace(usedNow))
	f := strings.ToLower(strings.TrimSpace(a.InForce))
	if u == "" || f == "" || u == f {
		return ""
	}
	return "★ the profile just applied was verified against " + short(u) + ", but this device will verify " +
		"its NEXT profile against " + short(f) + " — the key in force was NOT changed by this run. Only the " +
		"key file (PIN=/--pin-file, the fourth artefact the Console issues) puts a key in force; --pin and a " +
		"baked-in key verify this one profile and leave the device pinned to whoever it was pinned to before. " +
		"This install is correct and the next one will be refused"
}
