package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
)

func TestBuildInspectionPostureDecryptAll(t *testing.T) {
	groups := []knownbypass.Group{
		{Name: "apple", Description: "Apple", Patterns: []string{"*.icloud.com", "gsa.apple.com"}},
		{Name: "windows", Description: "Windows Update", Patterns: []string{"*.windowsupdate.com"}},
	}
	p := inspectionposture.Posture{Mode: inspectionposture.ModeDecryptAll, KnownBypassEnabled: true}
	// Engine: decrypt-all ("*"), bypass set contains the apple group's patterns but NOT the windows one.
	posture := buildInspectionPosture(p, []string{"*"}, []string{"*.icloud.com", "gsa.apple.com", "extra.example.com"}, groups)

	if posture.DefaultMode != "decrypt_all" {
		t.Fatalf("default_mode = %q, want decrypt_all", posture.DefaultMode)
	}
	if !posture.KnownBypassEnabled {
		t.Fatalf("known_bypass_enabled should reflect the posture (true)")
	}
	if len(posture.KnownBypassGroups) != 2 || !posture.KnownBypassGroups[0].Active || posture.KnownBypassGroups[1].Active {
		t.Fatalf("known groups active flags wrong: %+v", posture.KnownBypassGroups)
	}
	// The auth-decrypt presets are always listed (for the UI), none selected under decrypt-all here.
	if len(posture.AuthDecryptGroups) == 0 {
		t.Fatalf("auth_decrypt_groups presets should always be listed")
	}
}

func TestBuildInspectionPostureBypassDefault(t *testing.T) {
	p := inspectionposture.Posture{
		Mode:                   inspectionposture.ModeBypassDefault,
		DecryptAllowlistHosts:  []string{"wiki.corp"},
		DecryptAllowlistGroups: []string{"m365_auth"},
	}
	posture := buildInspectionPosture(p, []string{"wiki.corp", "login.microsoftonline.com"}, nil, nil)

	if posture.DefaultMode != "bypass_default" {
		t.Fatalf("default_mode = %q, want bypass_default", posture.DefaultMode)
	}
	if len(posture.DecryptAllowlistHosts) != 1 || posture.DecryptAllowlistHosts[0] != "wiki.corp" {
		t.Fatalf("decrypt_allowlist_hosts = %v", posture.DecryptAllowlistHosts)
	}
	var m365 *authDecryptGroupView
	for i := range posture.AuthDecryptGroups {
		if posture.AuthDecryptGroups[i].Name == "m365_auth" {
			m365 = &posture.AuthDecryptGroups[i]
		}
	}
	if m365 == nil || !m365.Selected {
		t.Fatalf("m365_auth should be present and selected, got %+v", posture.AuthDecryptGroups)
	}
}

func TestBuildInspectionPostureWarnsBypassDefaultNoAuth(t *testing.T) {
	// bypass_default with NO sign-in host in the intercept set -> warn (tenant restriction at risk).
	p := inspectionposture.Posture{Mode: inspectionposture.ModeBypassDefault}
	warned := buildInspectionPosture(p, []string{"wiki.corp"}, nil, nil)
	if len(warned.Warnings) == 0 {
		t.Fatalf("bypass_default with no auth host should warn")
	}
	// bypass_default WITH a sign-in host in the intercept set -> no warning.
	ok := buildInspectionPosture(p, []string{"login.microsoftonline.com"}, nil, nil)
	if len(ok.Warnings) != 0 {
		t.Fatalf("auth host present should clear the warning, got %v", ok.Warnings)
	}
	// decrypt_all -> never warns.
	da := buildInspectionPosture(inspectionposture.Posture{Mode: inspectionposture.ModeDecryptAll}, []string{"*"}, nil, nil)
	if len(da.Warnings) != 0 {
		t.Fatalf("decrypt_all should not warn, got %v", da.Warnings)
	}
}

func TestPatternsAllPresent(t *testing.T) {
	set := []string{"*.ICLOUD.com", " gsa.apple.com "} // engine may store mixed-case / padded
	if !patternsAllPresent([]string{"*.icloud.com", "gsa.apple.com"}, set) {
		t.Fatalf("normalized membership should match case/space-insensitively")
	}
	if patternsAllPresent([]string{"*.icloud.com", "missing.com"}, set) {
		t.Fatalf("a missing pattern must make the group inactive")
	}
	if patternsAllPresent(nil, set) {
		t.Fatalf("empty pattern set is not 'all present'")
	}
}
