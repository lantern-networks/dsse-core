//go:build windows

package main

import (
	"os"
	"strings"
)

// device_identity_default_windows.go — a machine already has a name.
//
// ★★★ THE OPERATOR'S POINT, AND IT IS THE RIGHT ONE (2026-08-25). --device-id was required with no default,
// so enrolling a machine meant INVENTING a name for it — "win-dev-1" — and then keeping that invented name
// true in every other place the organization already tracks machines. A second namespace, maintained by hand,
// for a thing that is already named.
//
// It also created a trap. An identity DSSE assigns is one DSSE can lose: removing "win-dev-1" left a
// tombstone nothing could lift, and that name was gone for good. The box was only recovered because somebody
// said "use the machine name" and it enrolled again as skusanagi-win10. The tombstone is fixed now; the
// second namespace is the part that should not have existed.
//
// ★ NOT UNIQUE IN GENERAL, AND THAT IS FINE HERE. Machine names are unique inside an organization in
// practice, enrolment is per-organization, and a second enrolment of the same identity is REFUSED rather than
// silently merged — so a collision is loud at the moment it happens instead of quiet forever.
//
// ★ A RENAMED MACHINE IS NO LONGER A NEW DEVICE (corrected 2026-08-25, same day). This comment used to say
// that renaming and re-enrolling produced a SECOND identity and left the first — true when it was written, and
// the reason the operator asked for renames to be tracked. The agent now reports something machine-unique
// alongside the name (machine_reference_windows.go), so a machine arriving under a new name is recognised and
// REFUSED rather than duplicated, and the refusal says which name it is already enrolled under.
//
// --device-id still wins when given: a deployment that has already standardised on its own identifiers keeps
// working, and this only decides what happens when nobody said.
func defaultDeviceIdentity() string {
	// The computer name as the OS itself reports it. On Windows this is what appears in directory services,
	// inventory and the ticket somebody files — which is the whole point of using it.
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return normalizeDeviceIdentity(name)
}

// normalizeDeviceIdentity trims and lower-cases, and nothing else.
//
// ★ IT DELIBERATELY DOES NOT REWRITE THE NAME. A normaliser that strips or substitutes characters produces an
// identity that no longer matches what the operator sees in their own inventory, which is the one property
// this change exists to get. Case is folded because the deployment already compares identities case-insensitively.
func normalizeDeviceIdentity(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
