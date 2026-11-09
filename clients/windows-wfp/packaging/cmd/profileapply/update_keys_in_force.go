package main

import "strings"

// splitProfileUpdateKeys flattens the profile's update-signing keys into single, lower-case keys.
//
// ★ ONE NORMALISATION FOR EVERY DECISION (2026-11-04). The updater reads --update-pin as a
// comma-separated set, so a profile element written as "B,A" is two keys to it. The first version compared the
// whole element "B,A" against the reserved keys, found no match, and then let the key-set validator and the
// updater split it — so the configuration key A became an update key. Every check now sees the keys the updater
// will trust, one by one.
func splitProfileUpdateKeys(keys []string) []string {
	out := []string{}
	for _, element := range keys {
		for _, k := range strings.Split(element, ",") {
			if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
				out = append(out, k)
			}
		}
	}
	return out
}

func reservedKeySet(reserved []string) map[string]bool {
	held := map[string]bool{}
	for _, r := range splitProfileUpdateKeys(reserved) {
		held[r] = true
	}
	return held
}

// profileUpdateKeysConflict reports whether any key the updater would trust is one of the reserved keys, so the
// caller can say why nothing was adopted.
func profileUpdateKeysConflict(keys []string, reserved ...string) bool {
	held := reservedKeySet(reserved)
	for _, k := range splitProfileUpdateKeys(keys) {
		if held[k] {
			return true
		}
	}
	return false
}

// profileUpdatePinSet turns the profile's update-signing keys into the DsseUpdater condition, or nil when the
// profile carries none, carries a key that is not a legal update key, or names a key that already holds another
// authority on this device.
//
// ★ ONE KEY, ONE PURPOSE (2026-11-04). The key that verifies this device's configuration and the
// key that signs its policy must never also authorise code that runs as SYSTEM. build-msi.ps1 refuses
// UpdatePin == Pin for a package built for one deployment; the profile route must refuse the same thing, or the
// rule would depend on how the package was delivered. reserved are those other keys.
//
// Platform-neutral so it can be tested without a service manager.
func profileUpdatePinSet(keys []string, reserved ...string) pinSet {
	clean := splitProfileUpdateKeys(keys)
	if len(clean) == 0 || profileUpdateKeysConflict(clean, reserved...) {
		return nil
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, k := range clean {
		if !seen[k] {
			seen[k] = true
			unique = append(unique, k)
		}
	}
	for _, purpose := range pinPurposes {
		if purpose.ValueName != "Updater_UpdatePin" {
			continue
		}
		// Each key on its own, so a malformed key cannot hide inside a set that validates as a whole.
		for _, k := range unique {
			if purpose.Validate(k) != nil {
				return nil
			}
		}
		if purpose.Validate(strings.Join(unique, ",")) != nil {
			return nil
		}
	}
	return pinSet{"Updater_UpdatePin": strings.Join(unique, ",")}
}
