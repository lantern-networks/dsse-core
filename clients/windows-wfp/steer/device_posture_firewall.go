package main

// firewallStatusFromProfiles classifies the three Windows firewall profile settings
// (Domain, Standard/Private, Public). A registry setting is not proof of which
// profile is currently active, so a mixed or unreadable set must not claim that
// the endpoint firewall is enabled or disabled for the current network.
// Each entry is 1 (enabled), 0 (disabled), or -1 (unknown/unreadable).
func firewallStatusFromProfiles(states [3]int8) string {
	allEnabled, allDisabled := true, true
	for _, state := range states {
		allEnabled = allEnabled && state == 1
		allDisabled = allDisabled && state == 0
	}
	if allEnabled {
		return "on"
	}
	if allDisabled {
		return "off"
	}
	return ""
}
